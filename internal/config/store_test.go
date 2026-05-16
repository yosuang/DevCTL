package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "settings.json"))
}

func TestStore_GetMissingKey(t *testing.T) {
	// #given: empty store
	s := newTestStore(t)

	// #when: get a key that doesn't exist
	_, err := s.Get("user.name")

	// #then: returns ErrKeyNotFound
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestStore_SetAndGet(t *testing.T) {
	// #given: empty store
	s := newTestStore(t)

	// #when: set a key then get it
	require.NoError(t, s.Set("user.name", "alice"))
	v, err := s.Get("user.name")

	// #then: returns the value
	require.NoError(t, err)
	require.Equal(t, "alice", v)
}

func TestStore_SetOverwritesExistingValue(t *testing.T) {
	// #given: store with a key
	s := newTestStore(t)
	require.NoError(t, s.Set("user.name", "first"))

	// #when: set same key again
	require.NoError(t, s.Set("user.name", "second"))

	// #then: value is the new one
	v, err := s.Get("user.name")
	require.NoError(t, err)
	require.Equal(t, "second", v)
}

func TestStore_UnsetRemovesKey(t *testing.T) {
	// #given: store with two keys
	s := newTestStore(t)
	require.NoError(t, s.Set("user.name", "alice"))
	require.NoError(t, s.Set("other.key", "other"))

	// #when: unset one key
	require.NoError(t, s.Unset("user.name"))

	// #then: that key is gone, the other remains
	_, err := s.Get("user.name")
	require.ErrorIs(t, err, ErrKeyNotFound)

	v, err := s.Get("other.key")
	require.NoError(t, err)
	require.Equal(t, "other", v)
}

func TestStore_UnsetMissingKey(t *testing.T) {
	// #given: empty store
	s := newTestStore(t)

	// #when: unset a key that doesn't exist
	err := s.Unset("nonexistent")

	// #then: returns ErrKeyNotFound
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestStore_ListReturnsSortedPairs(t *testing.T) {
	// #given: store with several keys added out of order
	s := newTestStore(t)
	require.NoError(t, s.Set("user.name", "alice"))
	require.NoError(t, s.Set("a.b.c", "abc"))
	require.NoError(t, s.Set("project.name", "devctl"))

	// #when: list
	pairs, err := s.List()

	// #then: sorted alphabetically by key
	require.NoError(t, err)
	require.Equal(t, []KeyValue{
		{Key: "a.b.c", Value: "abc"},
		{Key: "project.name", Value: "devctl"},
		{Key: "user.name", Value: "alice"},
	}, pairs)
}

func TestStore_ListEmpty(t *testing.T) {
	// #given: empty store
	s := newTestStore(t)

	// #when: list
	pairs, err := s.List()

	// #then: returns empty slice
	require.NoError(t, err)
	require.Empty(t, pairs)
}

func TestStore_CreatesFileOnFirstSet(t *testing.T) {
	// #given: a store with no file yet
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "settings.json")
	s := NewStore(path)

	// #when: set a key
	require.NoError(t, s.Set("k", "v"))

	// #then: file exists with expected contents
	require.FileExists(t, path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"k": "v"`)
}

func TestStore_HandlesEmptyFile(t *testing.T) {
	// #given: an empty file on disk
	path := filepath.Join(t.TempDir(), "settings.json")
	require.NoError(t, os.WriteFile(path, []byte(""), 0644))
	s := NewStore(path)

	// #when: get from it
	_, err := s.Get("anything")

	// #then: treated as empty store, not a parse error
	require.ErrorIs(t, err, ErrKeyNotFound)
}
