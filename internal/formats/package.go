package formats

import (
	"fmt"

	"devctl/pkg/pkgmgr"
)

// PackageFormat defines the package format used in import/export files.
// This is the external file format and does not include internal fields.
type PackageFormat struct {
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	InstalledBy pkgmgr.ManagerType `json:"installedBy"`
}

// Validate validates the package format.
func (p *PackageFormat) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("package name is required")
	}
	if p.Version == "" {
		return fmt.Errorf("package version is required")
	}
	if p.InstalledBy == "" {
		return fmt.Errorf("installedBy is required")
	}
	return nil
}
