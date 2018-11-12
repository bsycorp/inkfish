// We override the default goproxy actions so that we can use our own
// signing function TLSConfigFromCA

package inkfish

import (
	"github.com/elazarl/goproxy"
)

var (
	OkConnect       = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: TLSConfigFromCA(&goproxy.GoproxyCa)}
	MitmConnect     = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: TLSConfigFromCA(&goproxy.GoproxyCa)}
	HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(&goproxy.GoproxyCa)}
	RejectConnect   = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: TLSConfigFromCA(&goproxy.GoproxyCa)}
)
