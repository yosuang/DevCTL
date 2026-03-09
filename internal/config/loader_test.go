package config

import (
	"devctl/pkg/pkgmgr"
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
		configPath := filepath.Join(tempDir, "devctl.json")

		configContent := `{
  "dataDir": "/custom/data"
}`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadFromFile(tempDir)

		assert.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, "/custom/data", cfg.DataDir)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "devctl.json")

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
			DataDir: "/test/data",
		}

		err := SaveToFile(cfg, configDir)

		assert.NoError(t, err)

		configPath := filepath.Join(configDir, "devctl.json")
		assert.FileExists(t, configPath)

		loadedCfg, err := LoadFromFile(configDir)
		require.NoError(t, err)
		assert.Equal(t, cfg.DataDir, loadedCfg.DataDir)
	})

	t.Run("overwrites existing config file", func(t *testing.T) {
		tempDir := t.TempDir()

		oldCfg := &Config{DataDir: "/old"}
		err := SaveToFile(oldCfg, tempDir)
		require.NoError(t, err)

		newCfg := &Config{DataDir: "/new"}
		err = SaveToFile(newCfg, tempDir)
		require.NoError(t, err)

		loadedCfg, err := LoadFromFile(tempDir)
		require.NoError(t, err)
		assert.Equal(t, "/new", loadedCfg.DataDir)
	})
}

func TestConfig_CustomManagerMetadata(t *testing.T) {
	t.Run("saves and loads custom manager metadata", func(t *testing.T) {
		// #given a config with custom manager metadata
		tempDir := t.TempDir()

		cfg := &Config{
			DataDir: "/test/data",
			PackageManagers: map[pkgmgr.ManagerType]PackageManagerConfig{
				pkgmgr.ManagerTypeScoop: {
					Version:        "1.0.0",
					ExecutablePath: "/path/to/scoop",
					Custom: &CustomManagerMetadata{
						Buckets: map[string]string{
							"git":    "main",
							"nodejs": "extras",
						},
					},
				},
				pkgmgr.ManagerTypeBrew: {
					Version:        "4.0.0",
					ExecutablePath: "/usr/local/bin/brew",
					Custom: &CustomManagerMetadata{
						Taps: map[string]string{
							"kubectl": "homebrew/core",
							"helm":    "homebrew/core",
						},
					},
				},
			},
		}

		// #when saving and loading the config
		err := SaveToFile(cfg, tempDir)
		require.NoError(t, err)

		loadedCfg, err := LoadFromFile(tempDir)
		require.NoError(t, err)

		// #then custom metadata should be preserved
		require.NotNil(t, loadedCfg.PackageManagers)

		scoopCfg := loadedCfg.PackageManagers[pkgmgr.ManagerTypeScoop]
		require.NotNil(t, scoopCfg.Custom)
		require.NotNil(t, scoopCfg.Custom.Buckets)
		assert.Equal(t, "main", scoopCfg.Custom.Buckets["git"])
		assert.Equal(t, "extras", scoopCfg.Custom.Buckets["nodejs"])

		brewCfg := loadedCfg.PackageManagers[pkgmgr.ManagerTypeBrew]
		require.NotNil(t, brewCfg.Custom)
		require.NotNil(t, brewCfg.Custom.Taps)
		assert.Equal(t, "homebrew/core", brewCfg.Custom.Taps["kubectl"])
		assert.Equal(t, "homebrew/core", brewCfg.Custom.Taps["helm"])
	})

	t.Run("loads old config without custom field (backward compatibility)", func(t *testing.T) {
		// #given an old config JSON without custom field
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "devctl.json")

		oldConfigJSON := `{
  "dataDir": "/test/data",
  "packageManagers": {
    "scoop": {
      "version": "1.0.0",
      "executablePath": "/path/to/scoop"
    }
  }
}`
		err := os.WriteFile(configPath, []byte(oldConfigJSON), 0644)
		require.NoError(t, err)

		// #when loading the config
		loadedCfg, err := LoadFromFile(tempDir)

		// #then it should load successfully without errors
		require.NoError(t, err)
		require.NotNil(t, loadedCfg)
		assert.Equal(t, "/test/data", loadedCfg.DataDir)

		scoopCfg := loadedCfg.PackageManagers[pkgmgr.ManagerTypeScoop]
		assert.Equal(t, "1.0.0", scoopCfg.Version)
		assert.Equal(t, "/path/to/scoop", scoopCfg.ExecutablePath)
		assert.Nil(t, scoopCfg.Custom)
	})

	t.Run("omits empty custom field in JSON", func(t *testing.T) {
		// #given a config with empty custom metadata
		tempDir := t.TempDir()

		cfg := &Config{
			DataDir: "/test/data",
			PackageManagers: map[pkgmgr.ManagerType]PackageManagerConfig{
				pkgmgr.ManagerTypeScoop: {
					Version:        "1.0.0",
					ExecutablePath: "/path/to/scoop",
					Custom:         nil,
				},
			},
		}

		// #when saving the config
		err := SaveToFile(cfg, tempDir)
		require.NoError(t, err)

		// #then the JSON should not contain custom field
		configPath := filepath.Join(tempDir, "devctl.json")
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.NotContains(t, jsonStr, "custom")
	})
}
