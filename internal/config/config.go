package config

const (
	AppName = "devctl"
)

// Config holds the configuration for devctl.
type Config struct {
	Debug     bool   `json:"debug" env:"DEVCTL_DEBUG"`
	DataDir   string `json:"dataDir" env:"DEVCTL_HOME"`
	ConfigDir string `json:"configDir" env:"DEVCTL_CONFIG_DIR"`
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
}
