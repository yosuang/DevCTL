package cmd

import (
	"devctl/internal/config"
	"devctl/internal/packages"
	"fmt"

	"github.com/spf13/cobra"
)

func NewCmdInit(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration by detecting package managers",
		Long:  `Detects installed package managers and saves their information to the configuration file.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit(cfg)
		},
	}

	return cmd
}

func runInit(cfg *config.Config) error {
	detectResult := packages.DetectPackageManagers()
	packageManagers := map[config.PackageManager]config.PackageManagerConfig{}
	for _, p := range detectResult {
		packageManagers[p.ID] = config.PackageManagerConfig{
			ID:             p.ID,
			Version:        "",
			ExecutablePath: p.ExecutablePath,
		}
	}
	cfg.PackageManagers = packageManagers

	if err := config.SaveToFile(cfg, cfg.ConfigDir); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Println("\nPackage Manager Detection Results:")
	fmt.Println("-----------------------------------")
	for _, mgr := range detectResult {
		status := "✗ Not installed"
		if mgr.Installed {
			status = fmt.Sprintf("✓ Installed at: %s", mgr.ExecutablePath)
		}
		fmt.Printf("%-10s %s\n", mgr.ID, status)
	}

	configPath := fmt.Sprintf("%s/config.json", cfg.ConfigDir)
	fmt.Printf("\nConfiguration saved to: %s\n", configPath)

	return nil
}
