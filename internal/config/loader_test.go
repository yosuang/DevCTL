package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromFile(t *testing.T) {
	t.Run("returns nil when config file does not exist", func(t *testing.T) {
		tempDir := t.TempDir()

		cfg, err := LoadFromFile(tempDir)

		assert.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("loads valid JSON config file", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "config.json")

		configContent := `{
  "debug": true,
  "dataDir": "/custom/data",
  "configDir": "/custom/config"
}`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadFromFile(tempDir)

		assert.NoError(t, err)
		require.NotNil(t, cfg)
		assert.True(t, cfg.Debug)
		assert.Equal(t, "/custom/data", cfg.DataDir)
		assert.Equal(t, "/custom/config", cfg.ConfigDir)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "config.json")

		invalidJSON := `{invalid json`
		err := os.WriteFile(configPath, []byte(invalidJSON), 0644)
		require.NoError(t, err)

		cfg, err := LoadFromFile(tempDir)

		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})
}

func TestSaveToFile(t *testing.T) {
	t.Run("creates config directory and saves file", func(t *testing.T) {
		tempDir := t.TempDir()
		configDir := filepath.Join(tempDir, "subdir")

		cfg := &Config{
			Debug:     true,
			DataDir:   "/test/data",
			ConfigDir: "/test/config",
		}

		err := SaveToFile(cfg, configDir)

		assert.NoError(t, err)

		configPath := filepath.Join(configDir, "config.json")
		assert.FileExists(t, configPath)

		loadedCfg, err := LoadFromFile(configDir)
		require.NoError(t, err)
		assert.Equal(t, cfg.Debug, loadedCfg.Debug)
		assert.Equal(t, cfg.DataDir, loadedCfg.DataDir)
		assert.Equal(t, cfg.ConfigDir, loadedCfg.ConfigDir)
	})

	t.Run("overwrites existing config file", func(t *testing.T) {
		tempDir := t.TempDir()

		oldCfg := &Config{Debug: false, DataDir: "/old"}
		err := SaveToFile(oldCfg, tempDir)
		require.NoError(t, err)

		newCfg := &Config{Debug: true, DataDir: "/new"}
		err = SaveToFile(newCfg, tempDir)
		require.NoError(t, err)

		loadedCfg, err := LoadFromFile(tempDir)
		require.NoError(t, err)
		assert.True(t, loadedCfg.Debug)
		assert.Equal(t, "/new", loadedCfg.DataDir)
	})
}
