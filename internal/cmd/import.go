package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/internal/ui"
	"devctl/pkg/pkgmgr"
	"devctl/pkg/pkgmgr/scoop"
	"devctl/pkg/version"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewCmdImport(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import packages from JSON file",
		Long:  `Import packages from a JSON configuration file and install them using the configured package managers.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runImport(cfg, args[0])
		},
	}
	return cmd
}

func runImport(cfg *config.Config, filePath string) error {
	importConfig, err := loadImportConfig(filePath)
	if err != nil {
		return err
	}

	var validPackages []config.PackageConfig
	for _, pkg := range importConfig.Packages {
		if !isValidPackage(pkg) {
			continue
		}
		if pkg.InstalledBy == config.Pwsh {
			continue
		}
		if _, ok := cfg.PackageManagers[pkg.InstalledBy]; !ok {
			return fmt.Errorf("package manager %s not configured", pkg.InstalledBy)
		}
		validPackages = append(validPackages, pkg)
	}

	if len(validPackages) == 0 {
		fmt.Println("No valid packages to import")
		return nil
	}

	ctx := context.Background()
	var successfulPackages []config.PackageConfig

	packageInfos := make([]ui.PackageInfo, len(validPackages))
	for i, pkg := range validPackages {
		packageInfos[i] = ui.PackageInfo{
			Name:    pkg.Name,
			Version: pkg.Version,
		}
	}

	var tracker = ui.NewProgressTracker(packageInfos)
	tracker.Start()

	for i, pkg := range validPackages {
		tracker.StartPackage(i)

		mgrConfig := cfg.PackageManagers[pkg.InstalledBy]
		mgr, err := getManager(pkg.InstalledBy, mgrConfig.ExecutablePath)
		if err != nil {
			tracker.FailPackage(i, err)
			continue
		}

		if err := processPackage(ctx, mgr, pkg); err != nil {
			tracker.FailPackage(i, err)
			continue
		}

		tracker.CompletePackage(i)
		successfulPackages = append(successfulPackages, pkg)
	}

	tracker.Stop()

	// TODO bellow code should be handled by ui internal
	cfg.Packages = config.MergePackages(cfg.Packages, successfulPackages)

	if err := config.SaveToFile(cfg, cfg.ConfigDir); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	return nil
}

func loadImportConfig(filePath string) (*config.Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var importConfig config.Config
	if err := json.Unmarshal(data, &importConfig); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &importConfig, nil
}

func isValidPackage(pkg config.PackageConfig) bool {
	return pkg.Name != "" && pkg.Version != "" && pkg.InstalledBy != ""
}

func processPackage(ctx context.Context, mgr pkgmgr.Manager, pkg config.PackageConfig) error {
	installedPackages, err := mgr.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list packages: %w", err)
	}

	var installedPkg *pkgmgr.Package
	for i := range installedPackages {
		if installedPackages[i].Name == pkg.Name {
			installedPkg = &installedPackages[i]
			break
		}
	}

	if installedPkg != nil {
		if version.Equal(installedPkg.Version, pkg.Version) {
			return nil
		}

		if err := mgr.Uninstall(ctx, pkg.Name); err != nil {
			return fmt.Errorf("failed to uninstall: %w", err)
		}
	}

	if err := mgr.Install(ctx, pkg.Name); err != nil {
		return fmt.Errorf("failed to install: %w", err)
	}

	return nil
}

func getManager(pm config.PackageManager, _ string) (pkgmgr.Manager, error) {
	switch pm {
	case config.Scoop:
		return scoop.New(), nil
	default:
		return nil, fmt.Errorf("manager not implemented: %s", pm)
	}
}
