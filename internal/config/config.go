package config

const (
	AppName = "devctl"
)

// Config holds the configuration for devctl.
type Config struct {
	Debug           bool                                    `json:"-" env:"DEVCTL_DEBUG"`
	DataDir         string                                  `json:"dataDir,omitempty" env:"DEVCTL_HOME"`
	ConfigDir       string                                  `json:"configDir,omitempty" env:"DEVCTL_CONFIG_DIR"`
	Packages        []PackageConfig                         `json:"packages,omitempty"`
	PackageManagers map[PackageManager]PackageManagerConfig `json:"packageManagers,omitempty"`
}

type PackageConfig struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name,omitempty"`
	Version     string         `json:"version,omitempty"`
	InstalledBy PackageManager `json:"installedBy,omitempty"`
	Script      string         `json:"script,omitempty"`
	HomeDir     string         `json:"homeDir,omitempty"`
}

type PackageManagerConfig struct {
	ID             PackageManager `json:"id,omitempty"`
	Version        string         `json:"version,omitempty"`
	ExecutablePath string         `json:"executablePath,omitempty"`
}

type PackageManager string

const (
	Scoop PackageManager = "scoop"
	Pwsh  PackageManager = "pwsh"
)

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
}
