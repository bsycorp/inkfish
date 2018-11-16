package inkfish

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/elazarl/goproxy"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
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
	ConnectFilter    func(string, int) bool
	MetadataProvider MetadataProvider
	Proxy            *goproxy.ProxyHttpServer
	CertSigner       *CertSigner
	Actions          *Actions
}

func NewInkfish() *Inkfish {
	var this Inkfish
	clientTlsConfig := &tls.Config{InsecureSkipVerify: ClientInsecureSkipVerify}
	clientTransport := &http.Transport{
		TLSClientConfig: clientTlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	this.CertSigner = NewCertSigner(&goproxy.GoproxyCa)
	this.Actions = this.CertSigner.GetActions()
	this.Proxy = goproxy.NewProxyHttpServer()
	this.Proxy.Tr = clientTransport
	this.Proxy.OnRequest().HandleConnect(onConnect(&this))
	this.Proxy.OnRequest().Do(onRequest(&this))
	return &this
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
	proxy.Actions = proxy.CertSigner.GetActions()
	return nil
}

func defaultConnectFilter(host string, port int) bool {
	return port == 443
}

func connectDenied(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode:    403,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Body:          ioutil.NopCloser(bytes.NewBuffer([]byte(AccessDenied))),
		ContentLength: int64(len(AccessDenied)),
	}
}

func onConnect(proxy *Inkfish) goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostFields := strings.Split(host, ":")
		if len(hostFields) != 2 {
			proxy.logConnect(ctx, ConnectLogEntry{
				RemoteAddr:    ctx.Req.RemoteAddr,
				User:          "UNKNOWN",
				ConnectTarget: host,
				Result:        "REJECT",
				Reason:        "bad connect request",
			})
			return proxy.Actions.RejectConnect, host
		}
		connectHost := hostFields[0]
		connectPort, err := strconv.Atoi(hostFields[1])
		if err != nil {
			proxy.logConnect(ctx, ConnectLogEntry{
				RemoteAddr:    ctx.Req.RemoteAddr,
				User:          "UNKNOWN",
				ConnectTarget: host,
				Result:        "REJECT",
				Reason:        "bad port number",
			})
			ctx.Resp = connectDenied(ctx.Req)
			return proxy.Actions.RejectConnect, host
		}
		var allowed bool
		if proxy.ConnectFilter != nil {
			allowed = proxy.ConnectFilter(connectHost, connectPort)
		} else {
			allowed = defaultConnectFilter(connectHost, connectPort)
		}
		if !allowed {
			proxy.logConnect(ctx, ConnectLogEntry{
				RemoteAddr:    ctx.Req.RemoteAddr,
				User:          "UNKNOWN",
				ConnectTarget: host,
				Result:        "REJECT",
				Reason:        "denied by connect filter",
			})
			ctx.Resp = connectDenied(ctx.Req)
			return proxy.Actions.RejectConnect, host
		}

		// We allow all CONNECT calls to safe ports (e.g. 443) but perform access control
		// checks at the point of request. However, if the client has sent a proxy auth header,
		// we need to read that out now as it will not be sent on "tunneled" HTTP requests.

		var user string
		user, err = proxy.authenticateClient(ctx.Req)
		if err != nil {
			ctx.Warnf("client: %v: authentication error during connect: %v", ctx.Req.RemoteAddr, err)
		}
		// Stash the authenticated username against the proxy context iff the user did proxy-auth
		if strings.HasPrefix(user, "user:") {
			userData := map[string]string{
				"user": user,
				"host": host,
			}
			ctx.UserData = userData
		}

		// Search for an MITM bypass directive
		if proxy.bypassMitm(user, host) {
			proxy.logConnect(ctx, ConnectLogEntry{
				RemoteAddr:    ctx.Req.RemoteAddr,
				User:          user,
				ConnectTarget: host,
				Result:        "BYPASS",
			})
			return proxy.Actions.OkConnect, host
		}
		proxy.logConnect(ctx, ConnectLogEntry{
			RemoteAddr:    ctx.Req.RemoteAddr,
			User:          user,
			ConnectTarget: host,
			Result:        "MITM",
		})
		return proxy.Actions.MitmConnect, host
	})
}

func onRequest(proxy *Inkfish) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		deniedResponse := goproxy.NewResponse(req,
			goproxy.ContentTypeText,
			http.StatusForbidden,
			AccessDenied,
		)
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			// We don't support ftp://, gopher:// etc.
			proxy.logRequest(ctx, RequestLogEntry{
				RemoteAddr: ctx.Req.RemoteAddr,
				User:       "UNKNOWN",
				Method:     req.Method,
				Url:        req.URL,
				Result:     "DENIED",
				Reason:     "unsupported scheme",
			})
			return req, deniedResponse
		}
		var user string
		if req.URL.Scheme == "https" {
			// If this is an HTTPS request, we try to get cached creds from the CONNECT phase.
			userData, ok := ctx.UserData.(map[string]string)
			if ok {
				user = userData["user"]
			}
		}
		if req.URL.Scheme == "http" || user == "" {
			// This is a non-tunneled request or for whatever reason, we don't have cached creds.
			var err error
			user, err = proxy.authenticateClient(req)
			if err != nil {
				ctx.Warnf("client: %v: authentication error during request: %v", req.RemoteAddr, err)
				// We don't bail out, user will come back as INVALID and get rejected by ACL
			}
		}

		// One of the quirks of goproxy is that request URLs will come through looking
		// like "https://twitter.com:443/" if they came via MiTM. We fix this up a bit
		// to make sure that our URL filtering is not going to see extraneous ports in
		// requests when regex matching.
		if req.URL.Scheme == "https" && req.Host != req.URL.Host {
			// TODO: check for "domain fronting"
			req.URL.Host = req.Host
		}
		if proxy.permitsRequest(user, req.Method, req.URL.String()) {
			proxy.logRequest(ctx, RequestLogEntry{
				RemoteAddr: ctx.Req.RemoteAddr,
				User:       user,
				Method:     req.Method,
				Url:        req.URL,
				Result:     "ALLOWED",
			})
			return req, nil // Allow the request
		}

		// Fall through, failed
		proxy.logRequest(ctx, RequestLogEntry{
			RemoteAddr: ctx.Req.RemoteAddr,
			User:       user,
			Method:     req.Method,
			Url:        req.URL,
			Result:     "DENY",
			Reason:     "denied by policy",
		})
		return req, deniedResponse
	})
}
