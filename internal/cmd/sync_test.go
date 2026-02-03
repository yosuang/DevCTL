package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/pkg/pkgmgr"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockManager implements pkgmgr.Manager for testing
type mockManager struct {
	listFunc      func(ctx context.Context) ([]pkgmgr.Package, error)
	installFunc   func(ctx context.Context, names ...string) error
	uninstallFunc func(ctx context.Context, names ...string) error
}

func (m *mockManager) List(ctx context.Context) ([]pkgmgr.Package, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx)
	}
	return []pkgmgr.Package{}, nil
}

func (m *mockManager) Install(ctx context.Context, names ...string) error {
	if m.installFunc != nil {
		return m.installFunc(ctx, names...)
	}
	return pkgmgr.ErrUnsupported
}

func (m *mockManager) Uninstall(ctx context.Context, names ...string) error {
	if m.uninstallFunc != nil {
		return m.uninstallFunc(ctx, names...)
	}
	return pkgmgr.ErrUnsupported
}

func TestSync_MergePreservesExisting(t *testing.T) {
	// #given: Config with existing packages
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir: tmpDir,
		Packages: []config.PackageConfig{
			{Name: "existing-pkg", Version: "1.0.0", InstalledBy: pkgmgr.ManagerTypeScoop},
		},
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeScoop: {ExecutablePath: "scoop"},
		},
	}

	// Mock manager that returns new packages
	mockMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return []pkgmgr.Package{
				{Name: "new-pkg", Version: "2.0.0", Source: "scoop"},
			}, nil
		},
	}

	// #when: Running sync with mock manager
	err := runSyncWithManagers(cfg, map[pkgmgr.ManagerType]pkgmgr.Manager{
		pkgmgr.ManagerTypeScoop: mockMgr,
	})

	// #then: Both existing and new packages should be in config
	require.NoError(t, err)
	assert.Len(t, cfg.Packages, 2)

	pkgNames := make(map[string]bool)
	for _, pkg := range cfg.Packages {
		pkgNames[pkg.Name] = true
	}
	assert.True(t, pkgNames["existing-pkg"], "existing package should be preserved")
	assert.True(t, pkgNames["new-pkg"], "new package should be added")
}

func TestSync_SkipsUnsupportedManagers(t *testing.T) {
	// #given: Config with unsupported managers (apt, powershell, pwsh)
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir: tmpDir,
		Packages:  []config.PackageConfig{},
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeApt:        {ExecutablePath: "apt"},
			pkgmgr.ManagerTypePowerShell: {ExecutablePath: "powershell"},
			pkgmgr.ManagerTypePwsh:       {ExecutablePath: "pwsh"},
		},
	}

	// #when: Running sync (should skip all unsupported managers)
	err := runSync(cfg)

	// #then: Should succeed without error, no packages added
	require.NoError(t, err)
	assert.Len(t, cfg.Packages, 0)
}

func TestSync_ContinuesOnManagerListError(t *testing.T) {
	// #given: Config with two managers, one will fail
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir: tmpDir,
		Packages:  []config.PackageConfig{},
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeScoop: {ExecutablePath: "scoop"},
			pkgmgr.ManagerTypeBrew:  {ExecutablePath: "brew"},
		},
	}

	// Mock managers: scoop fails, brew succeeds
	failingMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return nil, errors.New("scoop list failed")
		},
	}
	successMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return []pkgmgr.Package{
				{Name: "brew-pkg", Version: "1.0.0", Source: "brew"},
			}, nil
		},
	}

	// #when: Running sync with one failing manager
	err := runSyncWithManagers(cfg, map[pkgmgr.ManagerType]pkgmgr.Manager{
		pkgmgr.ManagerTypeScoop: failingMgr,
		pkgmgr.ManagerTypeBrew:  successMgr,
	})

	// #then: Should succeed, only brew packages added
	require.NoError(t, err)
	assert.Len(t, cfg.Packages, 1)
	assert.Equal(t, "brew-pkg", cfg.Packages[0].Name)
	assert.Equal(t, pkgmgr.ManagerTypeBrew, cfg.Packages[0].InstalledBy)
}

func TestSync_EmptyManagerList(t *testing.T) {
	// #given: Config with manager that returns empty list
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir: tmpDir,
		Packages:  []config.PackageConfig{},
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeScoop: {ExecutablePath: "scoop"},
		},
	}

	mockMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return []pkgmgr.Package{}, nil
		},
	}

	// #when: Running sync with empty list
	err := runSyncWithManagers(cfg, map[pkgmgr.ManagerType]pkgmgr.Manager{
		pkgmgr.ManagerTypeScoop: mockMgr,
	})

	// #then: Should succeed with no packages
	require.NoError(t, err)
	assert.Len(t, cfg.Packages, 0)
}

func TestSync_ConfigSaveHappensEvenWithPartialFailure(t *testing.T) {
	// #given: Config with two managers, one fails
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigDir: tmpDir,
		Packages:  []config.PackageConfig{},
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeScoop: {ExecutablePath: "scoop"},
			pkgmgr.ManagerTypeBrew:  {ExecutablePath: "brew"},
		},
	}

	failingMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return nil, errors.New("failed")
		},
	}
	successMgr := &mockManager{
		listFunc: func(ctx context.Context) ([]pkgmgr.Package, error) {
			return []pkgmgr.Package{
				{Name: "pkg1", Version: "1.0.0", Source: "brew"},
			}, nil
		},
	}

	// #when: Running sync
	err := runSyncWithManagers(cfg, map[pkgmgr.ManagerType]pkgmgr.Manager{
		pkgmgr.ManagerTypeScoop: failingMgr,
		pkgmgr.ManagerTypeBrew:  successMgr,
	})

	// #then: Config should be saved with successful packages
	require.NoError(t, err)

	// Verify config file was written
	configPath := filepath.Join(tmpDir, config.AppName+".json")
	_, err = os.Stat(configPath)
	assert.NoError(t, err, "config file should exist")
}

func TestSync_ConvertPackageToConfig(t *testing.T) {
	// #given: A package from manager
	pkg := pkgmgr.Package{
		Name:    "test-pkg",
		Version: "1.2.3",
		Source:  "scoop",
	}

	// #when: Converting to PackageConfig
	result := convertToPackageConfig(pkg, pkgmgr.ManagerTypeScoop)

	// #then: Should have correct fields
	assert.Equal(t, "test-pkg", result.Name)
	assert.Equal(t, "1.2.3", result.Version)
	assert.Equal(t, pkgmgr.ManagerTypeScoop, result.InstalledBy)
}

func TestSync_FiltersSupportedManagers(t *testing.T) {
	// #given: Config with mixed managers
	cfg := &config.Config{
		PackageManagers: map[pkgmgr.ManagerType]config.PackageManagerConfig{
			pkgmgr.ManagerTypeScoop:      {ExecutablePath: "scoop"},
			pkgmgr.ManagerTypeBrew:       {ExecutablePath: "brew"},
			pkgmgr.ManagerTypeApt:        {ExecutablePath: "apt"},
			pkgmgr.ManagerTypePowerShell: {ExecutablePath: "powershell"},
		},
	}

	// #when: Filtering for sync-supported managers
	supported := filterSupportedManagers(cfg.PackageManagers)

	// #then: Should only include scoop and brew
	assert.Len(t, supported, 2)
	assert.Contains(t, supported, pkgmgr.ManagerTypeScoop)
	assert.Contains(t, supported, pkgmgr.ManagerTypeBrew)
	assert.NotContains(t, supported, pkgmgr.ManagerTypeApt)
	assert.NotContains(t, supported, pkgmgr.ManagerTypePowerShell)
	assert.NotContains(t, supported, pkgmgr.ManagerTypePwsh)
}
