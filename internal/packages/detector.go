package packages

import (
	"devctl/internal/config"
	"devctl/pkg/executil"
)

var knownManagers = []config.PackageManager{
	config.Scoop,
	config.Pwsh,
}

type PackageManagerInfo struct {
	ID             config.PackageManager
	Installed      bool
	ExecutablePath string
}

func DetectPackageManagers() map[config.PackageManager]PackageManagerInfo {
	managers := map[config.PackageManager]PackageManagerInfo{}

	for _, mgr := range knownManagers {
		path := executil.LookPath(string(mgr))

		managers[mgr] = PackageManagerInfo{
			ID:             mgr,
			Installed:      path != "",
			ExecutablePath: path,
		}
	}

	return managers
}
