// See also: https://github.com/elazarl/goproxy/pull/314
// And: https://github.com/elazarl/goproxy/pull/256 - This could be important; there's an fd leak

package inkfish

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"
)

const signerVersion = ":inkfish1"
const certLifetimeMinutes = 240   // Set the NotAfter to be now + this value
const certExpiresSoon = 30        // Count cert as expired if less than this many minutes to live
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
	defer certSigner.CertCacheMutex.Unlock()

	cachedCert, found := certSigner.CertCache[string(hash)]
	if found && time.Now().Add(certExpiresSoon * time.Minute).Before(cachedCert.Leaf.NotAfter) {
		return cachedCert, nil
	}

	// Slow path; the cert is either not there, or expiring soon.
	if x509ca, err = x509.ParseCertificate(certSigner.CA.Certificate[0]); err != nil {
		return
	}
	start := time.Now().Add(time.Duration(-5) * time.Minute)
	end := time.Now().Add(certLifetimeMinutes * time.Minute)

	randomSerial := make([]byte, 20)
	_, err = rand.Read(randomSerial)
	if err != nil {
		panic(err)
	}
	serial := new(big.Int)
	serial.SetBytes(randomSerial)
	x509cert := x509.Certificate{
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
			x509cert.IPAddresses = append(x509cert.IPAddresses, ip)
		} else {
			x509cert.DNSNames = append(x509cert.DNSNames, h)
			x509cert.Subject.CommonName = h
		}
	}
	var certpriv *rsa.PrivateKey
	if certpriv, err = rsa.GenerateKey(rand.Reader, rsaKeyBits); err != nil {
		return
	}
	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &x509cert, x509ca, &certpriv.PublicKey, certSigner.CA.PrivateKey); err != nil {
		return
	}
	leafCert := tls.Certificate{
		Certificate: [][]byte{derBytes, certSigner.CA.Certificate[0]},
		PrivateKey:  certpriv,
		Leaf: &x509cert,
	}
	certSigner.CertCache[string(hash)] = leafCert

	return leafCert, nil
}
