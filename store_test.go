package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistsOnlyCommittedTransactionsAndDetachesSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Update(func(state *ManagerState) error {
		state.Records = append(state.Records, ManagedRecord{Nonce: "one", AdminID: 1, Name: "original"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Records[0].Name = "mutated snapshot"
	if err = s.Update(func(state *ManagerState) error {
		state.Records[0].Name = "rejected"
		return errors.New("reject transaction")
	}); err == nil {
		t.Fatal("expected transaction rejection")
	}
	reopened, err := NewStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 || got.Records[0].Name != "original" {
		t.Fatalf("unexpected state: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state permissions %o", info.Mode().Perm())
	}
}

func TestStoreRefusesCorruptStateRatherThanDiscardingOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"records":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path); err == nil {
		t.Fatal("corrupt resource ownership was silently replaced")
	}
}
