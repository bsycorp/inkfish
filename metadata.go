package inkfish

import (
	"sync"
)

type MetadataProvider interface {
	Lookup(k string) (string, bool)
}

type MetadataCache struct {
	mutex *sync.Mutex
	cache *map[string]string
}

func NewMetadataCache() *MetadataCache {
	return &MetadataCache{
		mutex: &sync.Mutex{},
		cache: &map[string]string{},
	}
}

func (c *MetadataCache) Replace(newValues map[string]string) {
	// Atomically replace the cache contents
	privateCopy := make(map[string]string)
	for k, v := range newValues {
		privateCopy[k] = v
	}
	c.mutex.Lock()
	c.cache = &privateCopy
	c.mutex.Unlock()
}

func (c *MetadataCache) Lookup(k string) (string, bool) {
	// Look up a single key from the cache
	c.mutex.Lock()
	tag, ok := (*c.cache)[k]
	c.mutex.Unlock()
	return tag, ok
}
