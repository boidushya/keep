package server

import (
	"sync"
	"time"
)

// tokenCache holds freshly-minted token plaintexts so the script-download
// endpoint can include them. Entries expire automatically.
type tokenCache struct {
	mu    sync.Mutex
	items map[int]tokenCacheEntry
}

type tokenCacheEntry struct {
	plain     string
	expiresAt time.Time
}

func newTokenCache() *tokenCache {
	return &tokenCache{items: map[int]tokenCacheEntry{}}
}

func (c *tokenCache) set(id int, plain string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	c.items[id] = tokenCacheEntry{plain: plain, expiresAt: expiresAt}
}

func (c *tokenCache) get(id int) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	e, ok := c.items[id]
	if !ok {
		return "", false
	}
	return e.plain, true
}

func (c *tokenCache) gcLocked() {
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expiresAt) {
			delete(c.items, k)
		}
	}
}
