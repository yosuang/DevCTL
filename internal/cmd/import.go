package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/internal/formats"
	"devctl/internal/ui"
	"devctl/pkg/pkgmgr"
	"devctl/pkg/pkgmgr/scoop"
	"devctl/pkg/version"
	"fmt"

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
	importFile, err := formats.LoadManifestFile(filePath)
	if err != nil {
		return err
	}

	var validPackages []config.PackageConfig
	for _, pkg := range importFile.Packages {
		if pkg.InstalledBy != pkgmgr.ManagerTypeScoop {
			continue
		}
		if _, ok := cfg.PackageManagers[pkg.InstalledBy]; !ok {
			return fmt.Errorf("package manager %s not configured", pkg.InstalledBy)
		}
		validPackages = append(validPackages, pkg.ToConfig())
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

	// Show spinner during cache building phase
	prepSpinner := ui.NewPreparationSpinner()
	prepSpinner.Start("Preparing context")

	managerCache := make(map[pkgmgr.ManagerType]pkgmgr.Manager)
	installedCache := make(map[pkgmgr.ManagerType]map[string]*pkgmgr.Package)

	managerTypes := make(map[pkgmgr.ManagerType]bool)
	for _, pkg := range validPackages {
		if pkg.InstalledBy != "" {
			managerTypes[pkg.InstalledBy] = true
		}
	}

	for managerType := range managerTypes {
		mgrConfig, ok := cfg.PackageManagers[managerType]
		if !ok {
			prepSpinner.Stop()
			return fmt.Errorf("package manager %s not configured", managerType)
		}

		mgr, err := getManager(managerType, mgrConfig)
		if err != nil {
			prepSpinner.Stop()
			return fmt.Errorf("failed to create manager %s: %w", managerType, err)
		}
		managerCache[managerType] = mgr

		installedPackages, err := mgr.List(ctx)
		if err != nil {
			prepSpinner.Stop()
			return fmt.Errorf("failed to list packages for %s: %w", managerType, err)
		}

		installedMap := make(map[string]*pkgmgr.Package)
		for j := range installedPackages {
			installedMap[installedPackages[j].Name] = &installedPackages[j]
		}
		installedCache[managerType] = installedMap
	}

	prepSpinner.Stop()

	var tracker = ui.NewProgressTracker(packageInfos)
	tracker.Start()

	for i, pkg := range validPackages {
		tracker.StartPackage(i)

		if pkg.InstalledBy == "" {
			tracker.FailPackage(i, fmt.Errorf("manager type is required"))
			continue
		}

		mgr := managerCache[pkg.InstalledBy]
		status, note, err := processPackage(ctx, mgr, pkg, installedCache[pkg.InstalledBy])
		if err != nil {
			tracker.FailPackage(i, err)
			continue
		}

		if status == ui.StatusSkipped {
			tracker.SkipPackage(i, note)
		} else {
			tracker.CompletePackage(i, note)
		}

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

func processPackage(ctx context.Context, mgr pkgmgr.Manager, pkg config.PackageConfig, installedMap map[string]*pkgmgr.Package) (ui.PackageStatus, string, error) {
	installedPkg := installedMap[pkg.Name]

	if installedPkg != nil {
		if version.Equal(installedPkg.Version, pkg.Version) {
			return ui.StatusSkipped, "already installed", nil
		}

		if err := mgr.Uninstall(ctx, pkg.Name); err != nil {
			return ui.StatusFailed, "", fmt.Errorf("failed to uninstall: %w", err)
		}

		packageWithVersion := pkg.Name
		if pkg.Version != "" {
			packageWithVersion = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}

		if err := mgr.Install(ctx, packageWithVersion); err != nil {
			return ui.StatusFailed, "", fmt.Errorf("failed to install: %w", err)
		}

		installedMap[pkg.Name] = &pkgmgr.Package{
			Name:    pkg.Name,
			Version: pkg.Version,
			Source:  string(pkg.InstalledBy),
		}

		return ui.StatusSuccess, "reinstalled", nil
	}

	packageWithVersion := pkg.Name
	if pkg.Version != "" {
		packageWithVersion = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
	}

	if err := mgr.Install(ctx, packageWithVersion); err != nil {
		return ui.StatusFailed, "", fmt.Errorf("failed to install: %w", err)
	}

	installedMap[pkg.Name] = &pkgmgr.Package{
		Name:    pkg.Name,
		Version: pkg.Version,
		Source:  string(pkg.InstalledBy),
	}

	return ui.StatusSuccess, "installed", nil
}

func getManager(managerType pkgmgr.ManagerType, mgrConfig config.PackageManagerConfig) (pkgmgr.Manager, error) {
	if mgrConfig.ExecutablePath == "" {
		return nil, fmt.Errorf("executable path of %s not configured", managerType)
	}

	mgr, err := newPackageManager(managerType, mgrConfig.ExecutablePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager %s: %w", managerType, err)
	}
	return mgr, nil
}

func newPackageManager(managerType pkgmgr.ManagerType, executablePath string) (pkgmgr.Manager, error) {
	if managerType == pkgmgr.ManagerTypeScoop {
		return scoop.New(&scoop.Config{
			ExecutablePath: executablePath,
		}), nil
	}
	return nil, nil
}
