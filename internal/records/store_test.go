package records

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddListDeleteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.json")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := s.Add(Record{Name: "svc.internal", Type: "A", Value: "10.0.0.5"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got := s.Lookup("svc.internal", "A")
	if len(got) != 1 || got[0].Value != "10.0.0.5" {
		t.Fatalf("unexpected lookup result: %+v", got)
	}

	// Name should have been normalized to FQDN.
	if got[0].Name != "svc.internal." {
		t.Fatalf("expected name to be FQDN, got %q", got[0].Name)
	}

	// The file should now exist and be reloadable.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected records file to exist: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	if len(s2.List()) != 1 {
		t.Fatalf("expected 1 record after reload, got %d", len(s2.List()))
	}

	if err := s.Delete("svc.internal", "A", ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.Lookup("svc.internal", "A")) != 0 {
		t.Fatalf("expected no records after delete")
	}
}

func TestAddReplacesSameValue(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "records.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.Add(Record{Name: "x.com", Type: "A", Value: "1.1.1.1", TTL: 60})
	_ = s.Add(Record{Name: "x.com", Type: "A", Value: "1.1.1.1", TTL: 900})

	got := s.Lookup("x.com", "A")
	if len(got) != 1 {
		t.Fatalf("expected the second Add to replace the first, got %d records", len(got))
	}
	if got[0].TTL != 900 {
		t.Fatalf("expected TTL to be updated to 900, got %d", got[0].TTL)
	}
}
