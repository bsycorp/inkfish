package inkfish

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTrivialMetadataStuff(t *testing.T) {
	m := NewMetadataCache()
	_, ok := m.Lookup("192.168.0.1")
	assert.Equal(t, false, ok)

	m.Replace(map[string]string{
		"192.168.0.1": "MumbleService",
	})

	v, ok := m.Lookup("192.168.0.1")
	assert.Equal(t, true, ok)
	assert.Equal(t, "MumbleService", v)
}
