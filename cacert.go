package inkfish

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/elazarl/goproxy"
	"github.com/pkg/errors"
	"io/ioutil"
)

// Set the CA certificate presented by the proxy.
// Note that this will set the goproxy CA cert globally. There's no supported
// way to set this for only one goproxy instance.
func SetGlobalCAFromFiles(caCertFile, caKeyFile string) error {
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return errors.Wrap(err, "failed to read CA cert")
	}
	caKey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return errors.Wrap(err, "failed to read CA key")
	}
	return setCA(caCert, caKey)
}

func setCA(caCert, caKey []byte) error {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return errors.Wrap(err, "failed to create CA keypair")
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return errors.Wrap(err, "failed to parse CA certificate")
	}
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	return nil
}
