// See also: https://github.com/elazarl/goproxy/pull/314
// And: https://github.com/elazarl/goproxy/pull/284 - We add cert caching in a different way.
// And: https://github.com/elazarl/goproxy/pull/256 - This could be important; there's an fd leak

package inkfish

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const signerVersion = ":inkfish1"
const maxCertificateLifetimeDays = 84
const rsaKeyBits = 2048

type CertSigner struct {
	CA             *tls.Certificate
	TlsConfig      *tls.Config
	CertCache      map[string]tls.Certificate
	CertCacheMutex *sync.Mutex
}

func NewCertSigner(ca *tls.Certificate) *CertSigner {
	signer := CertSigner{}
	signer.CA = ca
	signer.TlsConfig = &tls.Config{
		InsecureSkipVerify: false,
	}
	signer.CertCache = map[string]tls.Certificate{}
	signer.CertCacheMutex = &sync.Mutex{}
	return &signer
}

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func (certSigner *CertSigner) TLSConfig() func(host string) (*tls.Config, error) {
	return func(host string) (*tls.Config, error) {
		var config tls.Config
		config = *certSigner.TlsConfig
		log.Printf("signing for %s", stripPort(host))
		cert, err := certSigner.signHost([]string{stripPort(host)})
		if err != nil {
			log.Printf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}
		config.Certificates = append(config.Certificates, cert)
		return &config, nil
	}
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha256.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func (certSigner *CertSigner) signHost(hosts []string) (cert tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Fast path; is it cached?
	hash := hashSorted(append(hosts, signerVersion))
	certSigner.CertCacheMutex.Lock()
	cachedCert, found := certSigner.CertCache[string(hash)]
	certSigner.CertCacheMutex.Unlock()
	if found {
		return cachedCert, nil
	}

	if x509ca, err = x509.ParseCertificate(certSigner.CA.Certificate[0]); err != nil {
		return
	}
	start := time.Now().Add(time.Duration(-5) * time.Minute)
	end := time.Now().AddDate(0, 0, maxCertificateLifetimeDays)
	if err != nil {
		panic(err)
	}

	randomSerial := make([]byte, 20)
	_, err = rand.Read(randomSerial)
	if err != nil {
		panic(err)
	}
	serial := new(big.Int)
	serial.SetBytes(randomSerial)
	template := x509.Certificate{
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"Inkfish MITM Proxy"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}
	var certpriv *rsa.PrivateKey
	if certpriv, err = rsa.GenerateKey(rand.Reader, rsaKeyBits); err != nil {
		return
	}
	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &certpriv.PublicKey, certSigner.CA.PrivateKey); err != nil {
		return
	}
	leafCert := tls.Certificate{
		Certificate: [][]byte{derBytes, certSigner.CA.Certificate[0]},
		PrivateKey:  certpriv,
	}
	certSigner.CertCacheMutex.Lock()
	certSigner.CertCache[string(hash)] = leafCert
	certSigner.CertCacheMutex.Unlock()

	return leafCert, nil
}
