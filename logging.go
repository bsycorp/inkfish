package inkfish

import (
	"fmt"
	"log"
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
	Url        url.URL
	Result     string
	Reason     string
}

const sessionId = 31337 // TODO

func (proxy *Inkfish) ctxPrintf(msg string, argv ...interface{}) {
	// 2 << 19 => 524288, max session id in logs before wrap-around
	log.Printf("[%06d] "+msg+"\n", append([]interface{}{sessionId & 2 << 19}, argv...)...)
}

func (proxy *Inkfish) ctxLogf(msg string, argv ...interface{}) {
	log.Printf("INFO: "+msg, argv...)
}

func (proxy *Inkfish) ctxWarnf(msg string, argv ...interface{}) {
	log.Printf("WARN: "+msg, argv...)
}

func (proxy *Inkfish) logConnect(e ConnectLogEntry) {
	msg := fmt.Sprintf("CONNECT: %v %v %v %v",
		e.RemoteAddr,
		e.User,
		e.ConnectTarget,
		e.Result,
	)
	if len(e.Reason) > 0 {
		msg = msg + " [" + e.Reason + "]"
	}
	log.Printf("%v", msg)
}

func sanitiseURL(u url.URL) string {
	var hasParamsHint string
	if len(u.Query()) > 0 {
		hasParamsHint = "?..."
	}
	sanitisedUrl := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}
	return sanitisedUrl.String() + hasParamsHint
}

func (proxy *Inkfish) logRequest(e RequestLogEntry) {
	msg := fmt.Sprintf("REQUEST: %v %v %v %v %v",
		e.RemoteAddr,
		e.User,
		e.Method,
		sanitiseURL(e.Url),
		e.Result,
	)
	if len(e.Reason) > 0 {
		msg = msg + " [" + e.Reason + "]"
	}
	log.Printf("%v", msg)
}
