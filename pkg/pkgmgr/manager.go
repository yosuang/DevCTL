package pkgmgr

import "context"

// Package represents a package managed by a package manager.
type Package struct {
	// Name is the name of the package.
	Name string
	// Version is the current version of the package.
	Version string
	// Description is a short summary of what the package does.
	Description string
	// Source is the origin of the package (e.g., "scoop", "brew", "apt").
	Source string
}

// Manager defines the interface for package management operations.
type Manager interface {
	// Install installs one or more packages by name.
	Install(ctx context.Context, names ...string) error
	// Uninstall uninstalls one or more packages by name.
	Uninstall(ctx context.Context, names ...string) error
	// List returns a list of currently installed packages.
	List(ctx context.Context) ([]Package, error)
}

type ManagerType string

const (
	ManagerTypeScoop ManagerType = "scoop"
	ManagerTypePwsh  ManagerType = "pwsh"
	ManagerTypeBrew  ManagerType = "brew"
	ManagerTypeApt   ManagerType = "apt"
)
