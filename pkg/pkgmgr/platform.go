package pkgmgr

import (
	"runtime"
	"slices"
)

// Platform represents an operating system platform.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformDarwin  Platform = "darwin"
	PlatformLinux   Platform = "linux"
)

// CurrentPlatform returns the current platform.
func CurrentPlatform() Platform {
	return Platform(runtime.GOOS)
}

// GetSupportedManagerTypes returns the list of package managers supported on the given platform.
func GetSupportedManagerTypes(p Platform) []ManagerType {
	switch p {
	case PlatformWindows:
		return []ManagerType{
			ManagerTypeScoop,
			ManagerTypePowerShell,
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

// GetCurrentPlatformManagerTypes returns the list of package managers supported on the current platform.
func GetCurrentPlatformManagerTypes() []ManagerType {
	return GetSupportedManagerTypes(CurrentPlatform())
}

// IsManagerSupported checks if a package manager is supported on the given platform.
func IsManagerSupported(mgr ManagerType, p Platform) bool {
	supported := GetSupportedManagerTypes(p)
	return slices.Contains(supported, mgr)
}
