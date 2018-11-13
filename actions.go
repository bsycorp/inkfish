// We override the default goproxy actions so that we can use our own
// signing function and have the CA be per-inkfish instance.

package inkfish

import (
	"crypto/tls"
	"github.com/elazarl/goproxy"
)

type Actions struct {
	OkConnect       *goproxy.ConnectAction
	MitmConnect     *goproxy.ConnectAction
	HTTPMitmConnect *goproxy.ConnectAction
	RejectConnect   *goproxy.ConnectAction
}

func NewActions(ca *tls.Certificate) *Actions {
	var actions Actions
	actions.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: TLSConfigFromCA(ca)}
	actions.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: TLSConfigFromCA(ca)}
	actions.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(ca)}
	actions.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: TLSConfigFromCA(ca)}
	return &actions
}
