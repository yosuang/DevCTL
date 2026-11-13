package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitReadsEnvAndCreatesNothing(t *testing.T) {
	// #given: an empty directory and debug enabled
	dir := t.TempDir()
	t.Setenv("DEVCTL_CONFIG_DIR", dir)
	t.Setenv("DEVCTL_DEBUG", "true")

	// #when: configuration is initialized
	cfg := Init()

	// #then: the directory is recorded and nothing is written
	if cfg.ConfigDir != dir {
		t.Fatalf("ConfigDir = %q", cfg.ConfigDir)
	}
	if !cfg.Debug {
		t.Fatal("Debug is false")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("created %s", entries[0].Name())
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); !os.IsNotExist(err) {
		t.Fatal("settings.json exists")
	}
}
