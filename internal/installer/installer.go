package installer

import (
	"context"
	"devctl/pkg/pkgmgr"
)

// Prerequisite represents a requirement check for installation.
type Prerequisite struct {
	Name    string
	Passed  bool
	Message string
}

// InstallProgress represents the progress of an installation.
type InstallProgress struct {
	Stage   string // "preparing", "downloading", "installing", "verifying", "complete"
	Message string
	Percent int // 0-100, -1 for indeterminate
}

// Installer defines the interface for package manager installation.
type Installer interface {
	// CanAutoInstall checks if automatic installation is supported.
	CanAutoInstall() (bool, error)

	// GetPrerequisites returns the list of prerequisite checks.
	GetPrerequisites() []Prerequisite

	// GetInstallCommand returns the command that will be executed (for transparency).
	GetInstallCommand() string

	// Install executes the installation process.
	// Sends progress updates through the progress channel.
	Install(ctx context.Context, progress chan<- InstallProgress) error

	// Verify checks if the installation was successful and returns the executable path.
	Verify() (string, error)
}

// GetInstaller returns an installer for the given package manager type.
func GetInstaller(managerType pkgmgr.ManagerType) Installer {
	switch managerType {
	case pkgmgr.ManagerTypeScoop:
		return NewScoopInstaller()
	default:
		return nil
	}
}
