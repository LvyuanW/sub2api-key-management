package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// StateStore holds service-owned resource mappings and idempotent batch progress.
// It never writes sub2api's database or configuration.
type StateStore struct {
	mu    sync.Mutex
	path  string
	state ManagerState
}

func NewStateStore(path string) (*StateStore, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("state path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &StateStore{path: path}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if err != nil || len(raw) > 64<<20 {
		return nil, errors.New("cannot read management state")
	}
	if err := json.Unmarshal(raw, &s.state); err != nil {
		return nil, errors.New("invalid management state; restore a backup")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return s, nil
}

func cloneState(state ManagerState) (ManagerState, error) {
	var result ManagerState
	raw, err := json.Marshal(state)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}

func (s *StateStore) Snapshot() (ManagerState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *StateStore) Update(fn func(*ManagerState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := cloneState(s.state)
	if err != nil {
		return err
	}
	if err = fn(&next); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	s.state = next
	if dir, openErr := os.Open(filepath.Dir(s.path)); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
