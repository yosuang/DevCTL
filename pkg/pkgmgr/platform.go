package pkgmgr

import (
	"runtime"
)

// Platform represents an operating system platform.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformDarwin  Platform = "darwin"
	PlatformLinux   Platform = "linux"
)

// GetCurrent returns the current platform.
func GetCurrent() Platform {
	return Platform(runtime.GOOS)
}

// GetSupportedManagers returns the list of package managers supported on the given platform.
func GetSupportedManagers(p Platform) []ManagerType {
	switch p {
	case PlatformWindows:
		return []ManagerType{
			ManagerTypeScoop,
			ManagerTypePwsh,
		}
	case PlatformDarwin:
		return []ManagerType{
			ManagerTypeBrew,
		}
	case PlatformLinux:
		return []ManagerType{
			ManagerTypeBrew,
			ManagerTypeApt,
		}
	default:
		return []ManagerType{}
	}
}

// IsManagerSupported checks if a package manager is supported on the given platform.
func IsManagerSupported(mgr ManagerType, p Platform) bool {
	supported := GetSupportedManagers(p)
	for _, m := range supported {
		if m == mgr {
			return true
		}
	}
	return false
}
