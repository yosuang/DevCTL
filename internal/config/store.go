// store.go implements a flat key-value store backed by settings.json.
// Keys are arbitrary dotted strings (e.g. "sync.remote.url"); the dot is
// part of the key, not a path into nested JSON.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

var ErrKeyNotFound = errors.New("key not found")

type Store struct {
	path string
}

type KeyValue struct {
	Key   string
	Value string
}

func NewStore(configFile string) *Store {
	return &Store{path: configFile}
}

func (s *Store) Get(key string) (string, error) {
	data, err := s.read()
	if err != nil {
		return "", err
	}
	v, ok := data[key]
	if !ok {
		return "", ErrKeyNotFound
	}
	return v, nil
}

func (s *Store) Set(key, value string) error {
	data, err := s.read()
	if err != nil {
		return err
	}
	data[key] = value
	return s.write(data)
}

func (s *Store) Unset(key string) error {
	data, err := s.read()
	if err != nil {
		return err
	}
	if _, ok := data[key]; !ok {
		return ErrKeyNotFound
	}
	delete(data, key)
	return s.write(data)
}

func (s *Store) List() ([]KeyValue, error) {
	data, err := s.read()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]KeyValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, KeyValue{Key: k, Value: data[k]})
	}
	return out, nil
}

func (s *Store) read() (map[string]string, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if data == nil {
		data = map[string]string{}
	}
	return data, nil
}

func (s *Store) write(data map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(s.path, buf, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
