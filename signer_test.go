package inkfish

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCertSigner(t *testing.T) {
	cs := NewCertSigner(&StubCA)
	now := time.Date(2010, 12, 1, 1, 1, 1, 0, time.UTC)
	cs.Now = func() time.Time {
		return now
	}
	hosts := []string{"fish.com"}

	// Sanity check: the soft cert lifetime must be less than the hard lifetime
	assert.Less(t, cs.CertSoftLifetime.Seconds(), cs.CertHardLifetime.Seconds())

	// It should issue a cert
	cert1, err := cs.signHost(hosts)
	assert.Nil(t, err)
	assert.NotNil(t, cert1)

	// The expiry time should correspond to now + cert hard lifetime
	assert.Equal(t, cert1.Leaf.NotAfter, now.Add(cs.CertHardLifetime))

	// It should not need a refresh
	assert.False(t, cs.needsRefresh(cert1.Leaf, now))

	// It should get the same cert from cache when the cert's not expired
	cert2, err := cs.signHost(hosts)
	assert.Nil(t, err)
	assert.NotNil(t, cert2)
	assert.Equal(t, cert1, cert2)

	// It _should_ need a refresh just after the end of the soft lifetime
	later := now.Add(cs.CertSoftLifetime).Add(1 * time.Second)
	assert.True(t, cs.needsRefresh(cert1.Leaf, later))

	// We should get a "fresh" cert after the soft lifetime has elapsed
	cs.Now = func() time.Time {
		return later
	}
	cert3, err := cs.signHost(hosts)
	assert.Nil(t, err)
	assert.NotNil(t, cert3)
	assert.NotEqual(t, cert1, cert3)
}
