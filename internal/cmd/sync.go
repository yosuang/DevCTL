package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/internal/ui"
	"devctl/internal/ui/widgets"
	"devctl/pkg/pkgmgr"
	"devctl/pkg/pkgmgr/brew"
	"devctl/pkg/pkgmgr/scoop"
	"fmt"

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
	out := ui.NewDefaultOutput()

	detectingSpinner := widgets.NewSpinner(out)
	detectingSpinner.Start("Detecting package managers")

	supportedTypes := filterSupportedManagers(cfg.PackageManagers)

	if len(supportedTypes) == 0 {
		out.Warning("No supported package managers detected")
		return nil
	}

	managers := make(map[pkgmgr.ManagerType]pkgmgr.Manager)
	for managerType, mgrConfig := range cfg.PackageManagers {
		if !contains(supportedTypes, managerType) {
			continue
		}

		mgr, err := createManager(managerType, mgrConfig.ExecutablePath)
		if err != nil {
			out.Warning(fmt.Sprintf("Failed to create manager %s: %v", managerType, err))
			continue
		}
		managers[managerType] = mgr
	}

	detectingSpinner.Stop()

	return runSyncWithManagers(cfg, managers, out)
}

func runSyncWithManagers(cfg *config.Config, managers map[pkgmgr.ManagerType]pkgmgr.Manager, out ui.Output) error {
	ctx := context.Background()
	var allNewPackages []config.PackageConfig
	syncCounts := make(map[pkgmgr.ManagerType]int)
	var warnings []string

	spinner := widgets.NewSpinner(out)
	spinner.Start("Scanning installed packages")

	for managerType, mgr := range managers {
		packages, err := mgr.List(ctx)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to list packages from %s: %v", managerType, err))
			continue
		}

		for _, pkg := range packages {
			pkgConfig := convertToPackageConfig(pkg, managerType)
			allNewPackages = append(allNewPackages, pkgConfig)
		}
		syncCounts[managerType] = len(packages)
	}

	spinner.Stop()
	for _, warning := range warnings {
		out.Warning(warning)
	}

	cfg.Packages = config.MergePackages(cfg.Packages, allNewPackages)

	saveConfigurationSpinner := widgets.NewSpinner(out)
	saveConfigurationSpinner.Start("Saving configuration")
	if err := config.SaveToFile(cfg, cfg.ConfigDir); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	saveConfigurationSpinner.Stop()

	totalSynced := 0
	for _, count := range syncCounts {
		if count > 0 {
			totalSynced += count
		}
	}

	if totalSynced > 0 {
		out.Printf("Synced %d packages successfully", totalSynced)
	} else {
		out.Print("No packages to sync")
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
