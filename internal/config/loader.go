package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LoadFromFile loads configuration from a JSON file.
// Returns nil if file doesn't exist (not an error - allows fallback to defaults).
// Returns error only for actual read/parse failures.
func LoadFromFile(configDir string) (*Config, error) {
	configPath := filepath.Join(configDir, fmt.Sprintf("%s.json", AppName))

	// If config file doesn't exist, return nil (not an error)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// SaveToFile saves configuration to a JSON file.
func SaveToFile(cfg *Config, configDir string) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, fmt.Sprintf("%s.json", AppName))

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
