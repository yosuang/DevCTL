package config

import "devctl/pkg/pkgmgr"

const (
	AppName = "devctl"
)

// Config holds the configuration for devctl.
type Config struct {
	Debug           bool                                        `json:"-" env:"DEVCTL_DEBUG"`
	DataDir         string                                      `json:"dataDir,omitempty" env:"DEVCTL_HOME"`
	ConfigDir       string                                      `json:"configDir,omitempty" env:"DEVCTL_CONFIG_DIR"`
	Packages        []PackageConfig                             `json:"packages,omitempty"`
	PackageManagers map[pkgmgr.ManagerType]PackageManagerConfig `json:"packageManagers,omitempty"`
}

type PackageConfig struct {
	Name        string             `json:"name,omitempty"`
	Version     string             `json:"version,omitempty"`
	InstalledBy pkgmgr.ManagerType `json:"installedBy,omitempty"`
	Script      string             `json:"script,omitempty"`
	HomeDir     string             `json:"homeDir,omitempty"`
}

type PackageManagerConfig struct {
	Type           pkgmgr.ManagerType `json:"type,omitempty"`
	Version        string             `json:"version,omitempty"`
	ExecutablePath string             `json:"executablePath,omitempty"`
}

// Merge merges another config into this one.
// Non-zero values from other override values in this config.
func (cfg *Config) Merge(other *Config) {
	if other == nil {
		return
	}

	if other.Debug {
		cfg.Debug = other.Debug
	}
	if other.DataDir != "" {
		cfg.DataDir = other.DataDir
	}
	if other.ConfigDir != "" {
		cfg.ConfigDir = other.ConfigDir
	}
	if other.PackageManagers != nil {
		if cfg.PackageManagers == nil {
			cfg.PackageManagers = make(map[pkgmgr.ManagerType]PackageManagerConfig)
		}
		for k, v := range other.PackageManagers {
			cfg.PackageManagers[k] = v
		}
	}
	if other.Packages != nil {
		cfg.Packages = other.Packages
	}
}
