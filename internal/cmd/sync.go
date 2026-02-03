package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/pkg/pkgmgr"
	"devctl/pkg/pkgmgr/brew"
	"devctl/pkg/pkgmgr/scoop"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewCmdSync(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync installed packages from package managers into config",
		Long:  `Detects installed packages from Scoop and Homebrew and merges them into the configuration file.`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSync(cfg)
		},
	}
	return cmd
}

func runSync(cfg *config.Config) error {
	supportedTypes := filterSupportedManagers(cfg.PackageManagers)

	if len(supportedTypes) == 0 {
		fmt.Println("No supported package managers detected")
		return nil
	}

	managers := make(map[pkgmgr.ManagerType]pkgmgr.Manager)
	for managerType, mgrConfig := range cfg.PackageManagers {
		if !contains(supportedTypes, managerType) {
			continue
		}

		mgr, err := createManager(managerType, mgrConfig.ExecutablePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create manager %s: %v\n", managerType, err)
			continue
		}
		managers[managerType] = mgr
	}

	return runSyncWithManagers(cfg, managers)
}

func runSyncWithManagers(cfg *config.Config, managers map[pkgmgr.ManagerType]pkgmgr.Manager) error {
	ctx := context.Background()
	var allNewPackages []config.PackageConfig
	syncCounts := make(map[pkgmgr.ManagerType]int)

	for managerType, mgr := range managers {
		packages, err := mgr.List(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to list packages from %s: %v\n", managerType, err)
			continue
		}

		for _, pkg := range packages {
			pkgConfig := convertToPackageConfig(pkg, managerType)
			allNewPackages = append(allNewPackages, pkgConfig)
		}
		syncCounts[managerType] = len(packages)
	}

	cfg.Packages = config.MergePackages(cfg.Packages, allNewPackages)

	if err := config.SaveToFile(cfg, cfg.ConfigDir); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	totalSynced := 0
	for managerType, count := range syncCounts {
		if count > 0 {
			fmt.Printf("Synced %d packages from %s\n", count, managerType)
			totalSynced += count
		}
	}

	if totalSynced > 0 {
		fmt.Printf("Total: %d packages synced\n", totalSynced)
	} else {
		fmt.Println("No packages to sync")
	}

	return nil
}

func filterSupportedManagers(managers map[pkgmgr.ManagerType]config.PackageManagerConfig) []pkgmgr.ManagerType {
	supportedForSync := []pkgmgr.ManagerType{
		pkgmgr.ManagerTypeScoop,
		pkgmgr.ManagerTypeBrew,
	}

	var result []pkgmgr.ManagerType
	for managerType := range managers {
		if contains(supportedForSync, managerType) {
			result = append(result, managerType)
		}
	}
	return result
}

func convertToPackageConfig(pkg pkgmgr.Package, managerType pkgmgr.ManagerType) config.PackageConfig {
	return config.PackageConfig{
		Name:        pkg.Name,
		Version:     pkg.Version,
		InstalledBy: managerType,
	}
}

func createManager(managerType pkgmgr.ManagerType, executablePath string) (pkgmgr.Manager, error) {
	switch managerType {
	case pkgmgr.ManagerTypeScoop:
		return scoop.New(&scoop.Config{
			ExecutablePath: executablePath,
		}), nil
	case pkgmgr.ManagerTypeBrew:
		return brew.New(&brew.Config{
			ExecutablePath: executablePath,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported manager: %s", managerType)
	}
}

func contains(slice []pkgmgr.ManagerType, item pkgmgr.ManagerType) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
