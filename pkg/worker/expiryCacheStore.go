package worker

import (
	"sync"
	"time"
	"unsafe"
)

type DomainExpiryCache struct {
	Store   map[int]CacheEntry // checker.c.id -> CacheEntry
	mutex   sync.Mutex
	maxSize int64
}

type CacheEntry struct {
	ExpiryDays int
	Timestamp  time.Time
}

var (
	domainExpiryStore *DomainExpiryCache
	once              sync.Once
)

// GetDomainExpiryStoreInstance returns signleton instance of DomainExpiryCache
func GetDomainExpiryStoreInstance() *DomainExpiryCache {
	if domainExpiryStore == nil {
		domainExpiryStore = &DomainExpiryCache{
			Store:   make(map[int]CacheEntry),
			mutex:   sync.Mutex{},
			maxSize: 500 * 1024 * 1024, // 500MB
		}
	}
	once.Do(func() {
		go domainExpiryStore.clearCachePeriodically()
	})
	return domainExpiryStore
}

// AddOrUpdateCache update the cache
func (d *DomainExpiryCache) AddOrUpdateCache(id int, entry CacheEntry) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.getCurrentCacheSize() > d.maxSize {
		d.clearCache()
	}
	d.Store[id] = entry
}

// GetCache returns the cache entry for a given id.
func (d *DomainExpiryCache) GetCache(id int) (CacheEntry, bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	entry, found := d.Store[id]
	return entry, found
}

// clearCachePeriodically clear cache evry 5 day
func (d *DomainExpiryCache) clearCachePeriodically() {
	ticker := time.NewTicker(5 * 24 * time.Hour)
	defer ticker.Stop()

	for {
		<-ticker.C
		d.clearCache()
	}
}

// clearCache clears the cache.
func (d *DomainExpiryCache) clearCache() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.Store = make(map[int]CacheEntry)
}

// getCurrentCacheSize estimates the current size of the cache in bytes.
func (d *DomainExpiryCache) getCurrentCacheSize() int64 {
	var totalSize int64
	for _, entry := range d.Store {
		entrySize := int64(unsafe.Sizeof(entry))
		totalSize += entrySize
	}
	return totalSize
}
