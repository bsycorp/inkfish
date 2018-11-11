package inkfish

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/elazarl/goproxy"
	"io/ioutil"
)

func SetCAFromFiles(caCertFile, caKeyFile string) error {
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return err
	}
	caKey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return err
	}
	return setCA(caCert, caKey)
}

func setCA(caCert, caKey []byte) error {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	return nil
}
