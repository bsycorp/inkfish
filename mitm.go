// https://github.com/kr/mitm/blob/master/mitm.go
// Copyright (c) 2015 Keith Rarick
// MIT License

package inkfish

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

type ConnectAction int
const (
	ConnectMitm ConnectAction = 1 + iota
	ConnectBypass
	ConnectDeny
)

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	// Wrap specifies a function for optionally wrapping upstream for
	// inspecting the decrypted HTTP request and response.
	Wrap func(connectReq *http.Request, scheme string, upstream http.Handler) http.Handler

	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CertSigner *CertSigner

	// TLSServerConfig specifies the tls.Config to use when generating leaf
	// cert using CA.
	TLSServerConfig *tls.Config

	// TLSClientConfig specifies the tls.Config to use when establishing
	// an upstream connection for proxying.
	TLSClientConfig *tls.Config

	// ConnectFilter will filter any CONNECT calls made to the proxy.
	ConnectFilter func(w http.ResponseWriter, req *http.Request) (action ConnectAction)

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Client requested a CONNECT tunnel from the proxy
	if r.Method == "CONNECT" {
		if p.ConnectFilter == nil {
			p.mitmConnect(w, r) // Mitm all by default
		} else {
			filterAction := p.ConnectFilter(w, r)
			if filterAction == ConnectMitm {
				p.mitmConnect(w, r)
			} else if filterAction == ConnectBypass {
				p.bypassConnect(w, r)
			} else if filterAction == ConnectDeny {
				; // The filter already sent the response
			}
		}
		return
	}
	// Regular HTTP proxy requests fall through to here
	rp := &httputil.ReverseProxy{
		Director:      httpDirector,
		FlushInterval: p.FlushInterval,
		Transport:     &http.Transport{
			DisableCompression: true,
		},
	}
	p.Wrap(nil, "http", rp).ServeHTTP(w, r)
}

func (p *Proxy) mitmConnect(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		name  = dnsName(r.Host)
	)

	if name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	provisionalCert, err := p.cert(name)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if p.TLSServerConfig != nil {
		*sConfig = *p.TLSServerConfig
	}
	sConfig.Certificates = []tls.Certificate{*provisionalCert}

	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()

	cConfig := new(tls.Config)
	if p.TLSClientConfig != nil {
		*cConfig = *p.TLSClientConfig

	}
	rp := &httputil.ReverseProxy{
		Director:      httpsDirector,
		Transport:     &http.Transport{
			TLSClientConfig: cConfig,
			DisableCompression: true,
		},
		FlushInterval: p.FlushInterval,
	}

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}

	http.Serve(&oneShotListener{wc}, p.Wrap(r, "https", rp))
	<-ch
}

func (p *Proxy) bypassConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func (p *Proxy) cert(names ...string) (*tls.Certificate, error) {
	cert, err := p.CertSigner.signHost(names)
	return &cert, err
}

// TODO: this should be 1.0 or 1.1 depending on what client asked for
var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

// handshake hijacks w's underlying net.Conn, responds to the CONNECT request
// and manually performs the TLS handshake. It returns the net.Conn or and
// error if any.
func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader); err != nil {
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
		// Explicitly disable User-Agent so it's not set to default value
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

// dnsName returns the DNS name in addr, if any.
func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// A oneShotListener implements net.Listener whos Accept only returns a
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
