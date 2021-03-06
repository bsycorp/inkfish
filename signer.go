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
const hardLifetime = 5 * time.Hour         // Published cert lifetime, from generation
const softLifetime = 4 * time.Hour         // Refresh after certificate is "this old"
const allowedClockDrift = 5 * time.Minute  // Issue this many minutes in past to forgive skew
const rsaKeyBits = 2048

type CertSigner struct {
	CA                  *tls.Certificate
	TlsConfig           *tls.Config
	CertCache           map[string]tls.Certificate
	CertCacheMutex      *sync.Mutex
	CertHardLifetime    time.Duration
	CertSoftLifetime    time.Duration
	AllowedClockDrift   time.Duration
	Now                 func() time.Time
}

func NewCertSigner(ca *tls.Certificate) *CertSigner {
	return &CertSigner{
		CA: ca,
		TlsConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		CertCache:           map[string]tls.Certificate{},
		CertCacheMutex:      &sync.Mutex{},
		CertHardLifetime:    hardLifetime,
		CertSoftLifetime:    softLifetime,
		AllowedClockDrift:   allowedClockDrift,
		Now:                 time.Now,
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

func (certSigner *CertSigner) needsRefresh(cert *x509.Certificate, now time.Time) bool {
	return cert.NotAfter.Sub(now) < certSigner.CertSoftLifetime
}

func (certSigner *CertSigner) signHost(hosts []string) (cert tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Fast path; is it cached?
	hash := hashSorted(append(hosts, signerVersion))
	certSigner.CertCacheMutex.Lock()
	defer certSigner.CertCacheMutex.Unlock()

	cachedCert, found := certSigner.CertCache[string(hash)]
	now := certSigner.Now()
	if found && !certSigner.needsRefresh(cachedCert.Leaf, now) {
		return cachedCert, nil
	}

	// Slow path; the cert is either not there, or expiring soon.
	if x509ca, err = x509.ParseCertificate(certSigner.CA.Certificate[0]); err != nil {
		return
	}

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
		NotBefore: now.Add(-certSigner.AllowedClockDrift),
		NotAfter:  now.Add(certSigner.CertHardLifetime),

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
		Leaf:        &x509cert,
	}
	certSigner.CertCache[string(hash)] = leafCert

	return leafCert, nil
}
