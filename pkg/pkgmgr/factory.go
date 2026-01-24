package pkgmgr

import "runtime"

var testGOOS = runtime.GOOS

var registry = make(map[string]func() Manager)

// Register registers a package manager factory for a specific platform.
// This is typically called from init() functions in platform-specific packages.
func Register(platform string, factory func() Manager) {
	registry[platform] = factory
}

// New creates a new package manager for the current platform.
// Returns ErrUnsupported if no manager is registered for the platform.
func New() (Manager, error) {
	factory, ok := registry[testGOOS]
	if !ok {
		return nil, ErrUnsupported
	}
	return factory(), nil
}
