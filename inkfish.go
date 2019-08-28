// CREDITS:
// * https://github.com/kr/mitm/blob/master/mitm.go
//     Copyright (c) 2015 Keith Rarick
//     MIT License
// * https://github.com/elazarl/goproxy
//     Copyright (c) 2012 Elazar Leibovich
//     BSD 3-Clause "New" or "Revised" License

package inkfish

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rcrowley/go-metrics"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	Registry         metrics.Registry
	AcceptedRequests metrics.Counter
	DeniedRequests   metrics.Counter
	MitmConnects     metrics.Counter
	BypassConnects   metrics.Counter
	DeniedConnects   metrics.Counter
	HandshakeErrors  metrics.Counter
	CertgenErrors    metrics.Counter
	OtherErrors      metrics.Counter
}

type Inkfish struct {
	Acls   []Acl
	Passwd []UserEntry

	// Maintains an ip -> tag map, for access control based on instance metadata
	MetadataProvider MetadataProvider

	// Decides whether to allow a CONNECT call by examining the host and port only
	ConnectPolicy func(host string, port int) bool

	// Generates leaf certs for TLS connections.
	CertSigner *CertSigner

	// TLSServerConfig specifies the tls.Config to use when generating leaf cert using CA.
	TLSServerConfig *tls.Config

	// FlushInterval specifies the flush interval to flush to the client while copying
	// the response body. If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// Metrics! Metrics!
	Metrics Metrics

	// Enable test mode (disables blocking of requests!)
	InsecureTestMode bool

	// Shared HTTP transport
	Transport *http.Transport
}

func NewInkfish(signer *CertSigner) *Inkfish {
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	proxy := &Inkfish{
		TLSServerConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		CertSigner: signer,
		Transport:  transport,
	}
	proxy.Metrics.Init()
	return proxy
}

func (m *Metrics) Init() {
	m.Registry = metrics.NewRegistry()

	metrics.RegisterRuntimeMemStats(m.Registry)

	m.MitmConnects = metrics.NewCounter()
	m.BypassConnects = metrics.NewCounter()
	m.DeniedConnects = metrics.NewCounter()
	m.AcceptedRequests = metrics.NewCounter()
	m.DeniedRequests = metrics.NewCounter()
	m.HandshakeErrors = metrics.NewCounter()
	m.CertgenErrors = metrics.NewCounter()
	m.OtherErrors = metrics.NewCounter()

	_ = m.Registry.Register("connect.mitm.count", m.MitmConnects)
	_ = m.Registry.Register("connect.bypass.count", m.BypassConnects)
	_ = m.Registry.Register("connect.denied.count", m.DeniedConnects)
	_ = m.Registry.Register("request.accepted.count", m.AcceptedRequests)
	_ = m.Registry.Register("request.denied.count", m.DeniedRequests)
	_ = m.Registry.Register("errors.handshake.count", m.HandshakeErrors)
	_ = m.Registry.Register("errors.certgen.count", m.CertgenErrors)
	_ = m.Registry.Register("errors.other.count", m.OtherErrors)
}

func (m *Metrics) StartCapture() {
	go metrics.CaptureRuntimeMemStats(m.Registry, time.Second*10)
	// go metrics.CaptureDebugGCStats(m.Registry, time.Second*10)
}

func (proxy *Inkfish) requestHandler(connectReq *http.Request, scheme string, upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed := proxy.filterRequest(connectReq, scheme, w, r); allowed {
			upstream.ServeHTTP(w, r)
		}
		// If the request was dropped, proxy.filterRequest sent a response.
	})
}

// Set the CA certificate presented by the proxy from PEM files
func (proxy *Inkfish) SetCAFromFiles(caCertFile, caKeyFile string) error {
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return errors.Wrap(err, "failed to read CA cert")
	}
	caKey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return errors.Wrap(err, "failed to read CA key")
	}
	return proxy.SetCA(caCert, caKey)
}

// Set the CA certificate presented by the proxy from bytes
func (proxy *Inkfish) SetCA(caCert, caKey []byte) error {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return errors.Wrap(err, "failed to create CA keypair")
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return errors.Wrap(err, "failed to parse CA certificate")
	}
	proxy.CertSigner = NewCertSigner(&ca)
	return nil
}

func defaultConnectPolicy(host string, port int) bool {
	// By default, block CONNECT to ports other than 443
	return port == 443
}

func (proxy *Inkfish) sendAccessDenied(w http.ResponseWriter, detail string) {
	// This sends blocked site URLs etc back in errors for diagnostic purposes.
	// We don't URL-escape because we don't actually expect responses to go back
	// to a browser. Inkfish is for machines, not humans so these errors will go
	// into log files. Doesn't hurt to set a few paranoia headers though.
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "script-src: 'none';")
	w.WriteHeader(403)
	_, err := w.Write([]byte("INKFISH PROXY DENIED REQUEST: " + detail))
	if err != nil {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Println("error writing DENIED response to client:", err)
	}
}

func (proxy *Inkfish) filterConnect(w http.ResponseWriter, req *http.Request) (action ConnectAction) {
	host := req.Host

	// Handle a CONNECT request
	hostFields := strings.Split(host, ":")
	if len(hostFields) != 2 {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    req.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "no port number",
		})
		proxy.Metrics.DeniedConnects.Inc(1)
		errMsg := fmt.Sprintf("CONNECT: no port number in: '%s'", host)
		proxy.sendAccessDenied(w, errMsg)
		return ConnectDeny
	}
	connectHost := hostFields[0]
	connectPort, err := strconv.Atoi(hostFields[1])
	if err != nil {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    req.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "bad port number",
		})
		proxy.Metrics.DeniedConnects.Inc(1)
		errMsg := fmt.Sprintf("CONNECT: bad port number in: '%s'", host)
		proxy.sendAccessDenied(w, errMsg)
		return ConnectDeny
	}
	var allowed bool
	if proxy.ConnectPolicy != nil {
		allowed = proxy.ConnectPolicy(connectHost, connectPort)
	} else {
		allowed = defaultConnectPolicy(connectHost, connectPort)
	}
	if !allowed {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    req.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "CONNECT denied by policy",
		})
		proxy.Metrics.DeniedConnects.Inc(1)
		errMsg := fmt.Sprintf("CONNECT denied by policy: '%s'", host)
		proxy.sendAccessDenied(w, errMsg)
		return ConnectDeny
	}

	// We allow all CONNECT calls to safe ports (e.g. 443) but perform access control
	// checks at the point of request. However, if the client has sent a proxy auth header,
	// we need to read that out now as it will not be sent on "tunneled" HTTP requests.

	var user string
	user, err = proxy.authenticateClient(req)
	if err != nil || user == authFailUser {
		proxy.ctxLogf("client: %v: authentication error during connect: %v", req.RemoteAddr, err)
		// We don't bail early here, we set authFailUser and let ACLs handle it all later. When you
		// fail during CONNECT / tunnel establishment, clients usually don't handle it well. Clients
		// will tend to handle errors better if we reject tunneled requests instead.
	}

	// Search for an MITM bypass directive
	if proxy.bypassMitm(user, host) {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    req.RemoteAddr,
			User:          user,
			ConnectTarget: host,
			Result:        "BYPASS",
		})
		proxy.Metrics.BypassConnects.Inc(1)
		return ConnectBypass
	} else {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    req.RemoteAddr,
			User:          user,
			ConnectTarget: host,
			Result:        "MITM",
		})
		proxy.Metrics.MitmConnects.Inc(1)
		return ConnectMitm
	}
}

func (proxy *Inkfish) filterRequest(connectReq *http.Request, scheme string, w http.ResponseWriter, req *http.Request) bool {
	var user string
	var err error
	if scheme == "https" {
		// Since this is an https request, basic auth should come from the CONNECT
		user, err = proxy.authenticateClient(connectReq)
		if err != nil || user == authFailUser {
			proxy.ctxLogf("client: %v: authentication error during request: %v", connectReq.RemoteAddr, err)
			// Don't bail out, user is set to INVALID and will be rejected by ACL
		}
	}
	if scheme == "http" {
		// This is a non-tunneled request
		user, err = proxy.authenticateClient(req)
		if err != nil || user == authFailUser {
			proxy.ctxLogf("client: %v: authentication error during request: %v", req.RemoteAddr, err)
			// Don't bail out, user is set to INVALID and will be rejected by ACL
		}
	}

	u := *req.URL
	u.Scheme = scheme
	u.Host = req.Host

	if aclEntry := proxy.findAclEntryThatAllowsRequest(user, req.Method, u.String()); aclEntry != nil {
		if !aclEntry.Quiet {
			proxy.logRequest(RequestLogEntry{
				RemoteAddr: req.RemoteAddr,
				User:       user,
				Method:     req.Method,
				Url:        u,
				Result:     "ALLOW",
			})
		}
		proxy.Metrics.AcceptedRequests.Inc(1)
		return true
	} else {
		proxy.logRequest(RequestLogEntry{
			RemoteAddr: req.RemoteAddr,
			User:       user,
			Method:     req.Method,
			Url:        u,
			Result:     "DENY",
			Reason:     "URL denied by policy",
		})
		proxy.Metrics.DeniedRequests.Inc(1)
		errMsg := fmt.Sprintf("URL denied by policy: %s", sanitiseURL(u))
		if proxy.InsecureTestMode {
			return true
		} else {
			proxy.sendAccessDenied(w, errMsg)
			return false
		}
	}
}

type ConnectAction int

const (
	ConnectMitm ConnectAction = 1 + iota
	ConnectBypass
	ConnectDeny
)

func (proxy *Inkfish) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Entry point for client requests
	if req.URL.Scheme == "" && req.URL.Path == "/healthz" {
		// Health check
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	} else if req.Method == "CONNECT" {
		// Client requested a CONNECT tunnel from the proxy
		filterAction := proxy.filterConnect(w, req)
		if filterAction == ConnectMitm {
			proxy.mitmConnect(w, req)
		} else if filterAction == ConnectBypass {
			proxy.bypassConnect(w, req)
		} else if filterAction == ConnectDeny {
			// The filter already sent the response
		}
	} else if req.URL.Scheme == "http" {
		// Regular HTTP proxy requests, non-secure
		rp := &httputil.ReverseProxy{
			Director:      httpDirector,
			FlushInterval: proxy.FlushInterval,
			Transport:     proxy.Transport,
		}
		proxy.requestHandler(nil, "http", rp).ServeHTTP(w, req)
	} else {
		// Any non-http request should be a CONNECT!
		errMsg := fmt.Sprintf("Unexpected scheme: %s", req.URL.Scheme)
		proxy.sendAccessDenied(w, errMsg)
	}
}

func (proxy *Inkfish) mitmConnect(w http.ResponseWriter, req *http.Request) {
	hostname, _, err := net.SplitHostPort(req.Host)
	if err != nil || hostname == "" {
		proxy.Metrics.CertgenErrors.Inc(1)
		log.Println("cannot determine cert name for " + req.Host)
		http.Error(w, "no upstream", 503)
		return
	}
	cert, err := proxy.CertSigner.signHost([]string{hostname})
	if err != nil {
		proxy.Metrics.CertgenErrors.Inc(1)
		log.Println("certgen:", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if proxy.TLSServerConfig != nil {
		*sConfig = *proxy.TLSServerConfig
	}
	sConfig.Certificates = []tls.Certificate{cert}

	cconn, err := proxy.handshake(w, req, sConfig)
	if err != nil {
		proxy.Metrics.HandshakeErrors.Inc(1)
		log.Println("handshake error:", req.Host, err)
		return
	}
	defer cconn.Close()

	rp := &httputil.ReverseProxy{
		Director: httpsDirector,
		Transport: proxy.Transport,
		FlushInterval: proxy.FlushInterval,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}

	err = http.Serve(&oneShotListener{wc}, proxy.requestHandler(req, "https", rp))
	if err != nil && err.Error() != "closed" {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Println("error serving client request:", req.Host, err)
	}
	<-ch
}

func (proxy *Inkfish) bypassConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Println("dial error in bypass:", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Println("hijacking not supported in bypass:", r.Host)
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Println("error performing hijack in bypass:", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err = clientConn.SetDeadline(time.Time{}); err != nil {
		log.Println("error clearing connection timeouts:", err)
	}
	dstUrl := fmt.Sprintf("dst %s", r.URL)
	go proxy.transfer(dstUrl, destConn, clientConn)
	go proxy.transfer(dstUrl, clientConn, destConn)
}

func (proxy *Inkfish) transfer(dstUrl string, destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	_, err := io.Copy(destination, source)
	// We're running transfers in both directions concurrently. It can happen that
	// one side falls out of the transfer loop and sister goroutine is still trying
	// to copy. This is common enough that we just ignore the error.
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		proxy.Metrics.OtherErrors.Inc(1)
		log.Printf("transfer error: %v: %v", dstUrl, err)
	}
}

func okHeader(r *http.Request) []byte {
	return []byte(fmt.Sprintf("HTTP/%d.%d 200 OK\r\n\r\n", r.ProtoMajor, r.ProtoMinor))
}

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func (proxy *Inkfish) handshake(w http.ResponseWriter, r *http.Request, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader(r)); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func unsetUserAgent(r *http.Request) {
	if _, ok := r.Header["User-Agent"]; !ok {
		// Explicitly disable User-Agent so that requests have the User-Agent of
		// the client. Otherwise we get the ua of golang's http client.
		r.Header.Set("User-Agent", "")
	}
}

func httpDirector(r *http.Request) {
	unsetUserAgent(r)
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	unsetUserAgent(r)
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

// A oneShotListener implements net.Listener whose Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}
