package packages

import (
	"devctl/pkg/executil"
	"devctl/pkg/pkgmgr"
)

// TODO obtain from pkgmgr.ManagerType with specified GOOS
var knownManagers = []pkgmgr.ManagerType{
	pkgmgr.ManagerTypeScoop,
	pkgmgr.ManagerTypePwsh,
}

type PackageManagerInfo struct {
	Type           pkgmgr.ManagerType
	Installed      bool
	ExecutablePath string
}

func DetectPackageManagers() map[pkgmgr.ManagerType]PackageManagerInfo {
	managers := map[pkgmgr.ManagerType]PackageManagerInfo{}

	for _, mgr := range knownManagers {
		path := executil.LookPath(string(mgr))

		managers[mgr] = PackageManagerInfo{
			Type:           mgr,
			Installed:      path != "",
			ExecutablePath: path,
		}
	}

	return managers
}
