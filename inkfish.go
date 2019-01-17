package inkfish

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	//"strconv"
	//"strings"
)

const AccessDenied = `
************************
* PROXY DENIED REQUEST *
************************
`

// Set this to true if you want the proxy's HTTP client to ignore TLS errors.
// Not recommended...
var ClientInsecureSkipVerify = false

type Inkfish struct {
	Acls             []Acl
	Passwd           []UserEntry
	MetadataProvider MetadataProvider
	ConnectFilter    func(host string, port int) bool
	Proxy            *Proxy
	CertSigner       *CertSigner
}

func NewInkfish(signer *CertSigner) *Inkfish {
	proxy := &Inkfish{
		Proxy: &Proxy{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			TLSServerConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			CertSigner: signer,
		},
	}
	proxy.Proxy.Wrap = func(connectReq *http.Request, scheme string, upstream http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowed := proxy.RequestFilter(connectReq, scheme, w, r); allowed {
				upstream.ServeHTTP(w, r)
			} else {
				// We dropped it...
			}
		})
	}
	proxy.Proxy.ConnectFilter = func(w http.ResponseWriter, r *http.Request) ConnectAction {
		return proxy.FilterConnect(w, r)
	}
	return proxy
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
	proxy.Proxy.CertSigner = NewCertSigner(&ca)
	return nil
}

func defaultConnectFilter(host string, port int) bool {
	return port == 443
}

func sendAccessDenied(w http.ResponseWriter) {
	w.WriteHeader(403)
	//w.Header().Add("Connection", "close")
	w.Write([]byte(AccessDenied))
}

func (proxy *Inkfish) FilterConnect(w http.ResponseWriter, r *http.Request) (action ConnectAction) {
	// TODO: what if host doesn't correspond with r.URI or whatever?
	host := r.Host

	// Handle a CONNECT request
	hostFields := strings.Split(host, ":")
	if len(hostFields) != 2 {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    r.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "bad connect request",
		})
		sendAccessDenied(w)
		return ConnectDeny
	}
	connectHost := hostFields[0]
	connectPort, err := strconv.Atoi(hostFields[1])
	if err != nil {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    r.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "bad port number",
		})
		sendAccessDenied(w)
		return ConnectDeny
	}
	var allowed bool
	if proxy.ConnectFilter != nil {
		allowed = proxy.ConnectFilter(connectHost, connectPort)
	} else {
		allowed = defaultConnectFilter(connectHost, connectPort)
	}
	if !allowed {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    r.RemoteAddr,
			User:          "UNKNOWN",
			ConnectTarget: host,
			Result:        "DENY",
			Reason:        "denied by connect filter",
		})
		sendAccessDenied(w)
		return ConnectDeny
	}

	// We allow all CONNECT calls to safe ports (e.g. 443) but perform access control
	// checks at the point of request. However, if the client has sent a proxy auth header,
	// we need to read that out now as it will not be sent on "tunneled" HTTP requests.

	var user string
	user, err = proxy.authenticateClient(r)
	if err != nil || user == badUser {
		proxy.ctxLogf("client: %v: authentication error during connect: %v", r.RemoteAddr, err)
		// We don't bail early here, we set badUser and let ACLs handle it all later. Why? Well, when you
		// fail during CONNECT / tunnel establishment, clients usually don't handle it well. Clients will
		// get much nicer errors if we reject tunneled requests instead.
	}

	// Search for an MITM bypass directive
	if proxy.bypassMitm(user, host) {
		proxy.logConnect(ConnectLogEntry{
			RemoteAddr:    r.RemoteAddr,
			User:          user,
			ConnectTarget: host,
			Result:        "BYPASS",
		})
		return ConnectBypass
	}
	proxy.logConnect(ConnectLogEntry{
		RemoteAddr:    r.RemoteAddr,
		User:          user,
		ConnectTarget: host,
		Result:        "MITM",
	})
	return ConnectMitm
}

func (proxy *Inkfish) RequestFilter(connectReq *http.Request, scheme string, w http.ResponseWriter, req *http.Request) bool {
	//fmt.Println("--------")
	//fmt.Println(req)
	var user string
	if scheme == "https" {
		// Since this is an http request, we authenticate from the connect request
		var err error
		//fmt.Println(connectReq)
		user, err = proxy.authenticateClient(connectReq)
		if err != nil || user == badUser {
			proxy.ctxLogf("client: %v: authentication error during request: %v", connectReq.RemoteAddr, err)
			// Don't bail out, user will come back as INVALID and get rejected by ACL
		}
	}
	if scheme == "http" {
		// This is a non-tunneled request or for whatever reason, we don't have cached creds.
		var err error
		user, err = proxy.authenticateClient(req)
		//fmt.Println("Authenticated as: " + user)
		if err != nil || user == badUser {
			proxy.ctxLogf("client: %v: authentication error during request: %v", req.RemoteAddr, err)
			// Don't bail out, user will come back as INVALID and get rejected by ACL
		}
	}

	aclUrl := *req.URL
	aclUrl.Scheme = scheme
	aclUrl.Host = req.Host

	if proxy.permitsRequest(user, req.Method, aclUrl.String()) {
		proxy.logRequest(RequestLogEntry{
			RemoteAddr: req.RemoteAddr,
			User:       user,
			Method:     req.Method,
			Url:        &aclUrl,
			Result:     "ALLOW",
		})
		return true
	}

	// Fall through, failed
	proxy.logRequest(RequestLogEntry{
		RemoteAddr: req.RemoteAddr,
		User:       user,
		Method:     req.Method,
		Url:        &aclUrl,
		Result:     "DENY",
		Reason:     "denied by policy",
	})
	sendAccessDenied(w)
	return false
}
