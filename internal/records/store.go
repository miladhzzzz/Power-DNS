// Package records implements Power-DNS's local authoritative overrides: a
// small set of names you want resolved locally instead of via the relay.
//
// v1's README promised "custom DNS record management via API endpoints for
// adding, deleting, and showing DNS records in the hosts file of the
// server" and "integration with Kubernetes (k8s) CoreDNS to resolve local
// names to services", but neither existed in code: internal/k8s/client.go
// was an empty package, and there was no hosts-file logic anywhere.
//
// v2 implements the record management half directly and drops the
// bespoke k8s client in favor of a documented integration point: anything
// that can make an HTTP PUT (a shell script, a small controller watching
// Kubernetes Services, CoreDNS itself) can push name -> address mappings in
// here, and the resolver will answer them authoritatively before ever
// touching the relay. That is less code, is testable without a cluster, and
// works with more than just Kubernetes.
package records

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Record is one authoritative override.
type Record struct {
	Name  string `json:"name"`  // e.g. "grafana.internal."
	Type  string `json:"type"`  // "A", "AAAA", "CNAME", or "TXT"
	Value string `json:"value"` // an IP, a target name, or text, matching Type
	TTL   uint32 `json:"ttl"`   // seconds; 0 means "use a sane default"
}

// Store is a JSON-file-backed, in-memory table of Records, safe for
// concurrent use.
type Store struct {
	path string

	mu      sync.RWMutex
	records map[string][]Record // keyed by dns.Fqdn(Name)+"|"+Type
}

// Open loads an existing records file at path, or starts empty if it
// doesn't exist yet. The file is created on the first write.
func Open(path string) (*Store, error) {
	s := &Store{path: path, records: make(map[string][]Record)}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading records file %q: %w", path, err)
	}
	var list []Record
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parsing records file %q: %w", path, err)
	}
	for _, r := range list {
		s.records[indexKey(r.Name, r.Type)] = append(s.records[indexKey(r.Name, r.Type)], r)
	}
	return s, nil
}

func indexKey(name, typ string) string { return fqdn(name) + "|" + typ }

func fqdn(name string) string {
	if len(name) == 0 || name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

// Lookup returns every record matching (name, type).
func (s *Store) Lookup(name, typ string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Record(nil), s.records[indexKey(name, typ)]...)
}

// List returns every record currently stored, sorted for stable output.
func (s *Store) List() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0)
	for _, recs := range s.records {
		out = append(out, recs...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Add inserts or replaces a record with the same (Name, Type, Value) and
// persists the store to disk.
func (s *Store) Add(r Record) error {
	r.Name = fqdn(r.Name)
	if r.TTL == 0 {
		r.TTL = 300
	}
	s.mu.Lock()
	k := indexKey(r.Name, r.Type)
	existing := s.records[k]
	replaced := false
	for i, e := range existing {
		if e.Value == r.Value {
			existing[i] = r
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, r)
	}
	s.records[k] = existing
	s.mu.Unlock()
	return s.persist()
}

// Delete removes every record matching (name, type[, value]). An empty
// value deletes all records for that (name, type).
func (s *Store) Delete(name, typ, value string) error {
	s.mu.Lock()
	k := indexKey(name, typ)
	if value == "" {
		delete(s.records, k)
	} else {
		existing := s.records[k]
		out := existing[:0]
		for _, e := range existing {
			if e.Value != value {
				out = append(out, e)
			}
		}
		if len(out) == 0 {
			delete(s.records, k)
		} else {
			s.records[k] = out
		}
	}
	s.mu.Unlock()
	return s.persist()
}

// persist rewrites the whole records file. Called on every mutation; record
// counts here are expected to be small (hundreds, not millions), so this is
// simpler and safer than incremental updates.
func (s *Store) persist() error {
	s.mu.RLock()
	all := make([]Record, 0)
	for _, recs := range s.records {
		all = append(all, recs...)
	}
	s.mu.RUnlock()

	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
