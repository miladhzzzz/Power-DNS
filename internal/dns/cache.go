package dns

import (
	"encoding/gob"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Cache struct {
	mutex     sync.RWMutex
	data      map[string]*cachedItem
	expiry    time.Duration
	filePath  string
}

type cachedItem struct {
	Msg      *dns.Msg
	ExpireAt time.Time
}

func NewCache(expiry time.Duration, filePath string) (*Cache, error) {
	cache := &Cache{
		data:     make(map[string]*cachedItem),
		expiry:   expiry,
		filePath: filePath,
	}
	err := cache.loadFromFile()
	return cache, err
}

func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, ok := c.data[key]
	if !ok || time.Now().After(item.ExpireAt) {
		return nil, false
	}
	return item.Msg, true
}

func (c *Cache) Set(key string, msg *dns.Msg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data[key] = &cachedItem{
		Msg:      msg,
		ExpireAt: time.Now().Add(c.expiry),
	}
	// Save cache to file after every update
	go c.saveToFile()
}

func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	// Save cache to file after every delete
	go c.saveToFile()
}

func (c *Cache) loadFromFile() error {
	// Check if cache file exists
	if _, err := os.Stat(c.filePath); os.IsNotExist(err) {
		return nil // Cache file doesn't exist, nothing to load
	}

	// Open cache file
	file, err := os.Open(c.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode cache data
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&c.data); err != nil {
		return err
	}

	return nil
}

func (c *Cache) saveToFile() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Create or truncate cache file
	file, err := os.Create(c.filePath)
	if err != nil {
		fmt.Println("Error creating cache file:", err)
		return err
	}
	defer file.Close()

	// Encode cache data
	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(c.data); err != nil {
		fmt.Println("Error encoding cache data:", err)
		return err
	}

	return nil
}