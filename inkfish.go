package inkfish

import (
	"bytes"
	"crypto/tls"
	"github.com/elazarl/goproxy"
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
	Acls          []Acl
	Passwd        []UserEntry
	ConnectFilter func(string, int) bool
	MetadataProvider MetadataProvider
	Proxy            *goproxy.ProxyHttpServer
}

func NewInkfish() *Inkfish {
	var this Inkfish
	clientTlsConfig := &tls.Config{InsecureSkipVerify: ClientInsecureSkipVerify}
	clientTransport := &http.Transport{
		TLSClientConfig: clientTlsConfig,
		Proxy: http.ProxyFromEnvironment,
	}
	this.Proxy = goproxy.NewProxyHttpServer()
	this.Proxy.Tr = clientTransport
	this.Proxy.OnRequest().HandleConnect(onConnect(&this))
	this.Proxy.OnRequest().Do(onRequest(&this))
	return &this
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
			ctx.Warnf("bad connect request for '%v'", host)
			return RejectConnect, host
		}
		connectHost := hostFields[0]
		connectPort, err := strconv.Atoi(hostFields[1])
		if err != nil {
			ctx.Warnf("bad port in connect request for '%v': '%v'", host, connectPort)
			ctx.Resp = connectDenied(ctx.Req)
			return RejectConnect, host
		}

		var allowed bool
		if proxy.ConnectFilter != nil {
			allowed = proxy.ConnectFilter(connectHost, connectPort)
		} else {
			allowed = defaultConnectFilter(connectHost, connectPort)
		}
		if !allowed {
			ctx.Warnf("client: %v: connect to %v port %v rejected by connect policy",
				ctx.Req.RemoteAddr, connectHost, connectPort)
			ctx.Resp = connectDenied(ctx.Req)
			return RejectConnect, host
		}

		// We allow all CONNECT calls to safe ports (e.g. 443) but perform access control
		// checks at the point of request. However, if the client has sent a proxy auth header,
		// we need to read that out now as it will not be sent on "tunneled" HTTP requests.

		var user string
		user, err = proxy.authenticateClient(ctx.Req)
		if err != nil {
			ctx.Warnf("client: %v: authentication error during connect: %v", ctx.Req.RemoteAddr, err)
		}
		// Stash the authenticated username against the proxy context
		userData := map[string]string{
			"user": user,
			"host": host,
		}
		ctx.UserData = userData
		return MitmConnect, host
	})
}

func onRequest(proxy *Inkfish) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		user := ""
		deniedResponse := goproxy.NewResponse(req, goproxy.ContentTypeText,
			http.StatusForbidden, AccessDenied)

		if req.URL.Scheme == "https" {
			// If this is an HTTPS request, we expect to use creds saved during
			// the proxy CONNECT phase.
			userData, ok := ctx.UserData.(map[string]string)
			if ok {
				user = userData["user"]
			}
		} else if req.URL.Scheme == "http" {
			// This is not a tunneled request so we invoke our auth logic for
			// the specific request.
			var err error
			user, err = proxy.authenticateClient(req)
			if err != nil {
				ctx.Warnf("client: %v: authentication error during request: %v", req.RemoteAddr, err)
			}
		} else {
			// We don't support ftp://, gopher:// etc.
			return req, deniedResponse
		}
		if user == "" {
			user = "ANONYMOUS"
		}
		// One of the quirks of goproxy is that request URLs will come through looking
		// like "https://twitter.com:443/" if they came via MiTM. We fix this up a bit
		// to make sure that our URL filtering is not going to see extraneous ports in
		// requests when regex matching.
		if req.URL.Scheme == "https" && req.Host != req.URL.Host {
			// TODO: check for "domain fronting"
			req.URL.Host = req.Host
		}
		if proxy.permits(user, req.Method, req.URL.String()) {
			return req, nil // Allow the request
		}
		return req, deniedResponse
	})
}
