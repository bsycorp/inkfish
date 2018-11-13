package inkfish

import (
	"fmt"
	"github.com/elazarl/goproxy"
	"net/url"
)

type ConnectLogEntry struct {
	RemoteAddr    string
	User          string
	ConnectTarget string
	Result        string
	Reason        string
}

type RequestLogEntry struct {
	RemoteAddr string
	User       string
	Method     string
	Url        *url.URL
	Result     string
	Reason     string
}

func (proxy *Inkfish) ctxPrintf(ctx *goproxy.ProxyCtx, msg string, argv ...interface{}) {
	proxy.Proxy.Logger.Printf("[%03d] "+msg+"\n", append([]interface{}{ctx.Session & 0xFF}, argv...)...)
}

func (proxy *Inkfish) ctxLogf(ctx *goproxy.ProxyCtx, msg string, argv ...interface{}) {
	proxy.ctxPrintf(ctx, "INFO: "+msg, argv...)
}

func (proxy *Inkfish) ctxWarnf(ctx *goproxy.ProxyCtx, msg string, argv ...interface{}) {
	proxy.ctxPrintf(ctx, "WARN: "+msg, argv...)
}

func (proxy *Inkfish) logConnect(ctx *goproxy.ProxyCtx, e ConnectLogEntry) {
	msg := fmt.Sprintf("CONNECT: %v %v %v %v",
		e.RemoteAddr,
		e.User,
		e.ConnectTarget,
		e.Result,
	)
	if len(e.Reason) > 0 {
		msg = msg + " [" + e.Reason + "]"
	}
	proxy.ctxLogf(ctx, "%v", msg)
}

func (proxy *Inkfish) logRequest(ctx *goproxy.ProxyCtx, e RequestLogEntry) {
	var hasParamsHint string
	if len(e.Url.Query()) > 0 {
		hasParamsHint = "?..."
	}
	sanitisedUrl := url.URL{
		Scheme: e.Url.Scheme,
		Host:   e.Url.Host,
		Path:   e.Url.Path,
	}
	urlToLog := sanitisedUrl.String() + hasParamsHint
	msg := fmt.Sprintf("REQUEST: %v %v %v %v %v",
		e.RemoteAddr,
		e.User,
		e.Method,
		urlToLog,
		e.Result,
	)
	if len(e.Reason) > 0 {
		msg = msg + " [" + e.Reason + "]"
	}
	proxy.ctxLogf(ctx, "%v", msg)
}
