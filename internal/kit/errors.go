package kit

import "errors"

var (
	ErrManifestNotFound   = errors.New("kit manifest not found")
	ErrNotTracked         = errors.New("config not tracked")
	ErrInvalidKeyName     = errors.New("key must be UPPER_SNAKE_CASE")
	ErrPackageNotFound    = errors.New("package not found in group")
	ErrPackageExists      = errors.New("package already exists in group")
	ErrInvalidPlaceholder = errors.New("invalid placeholder syntax")
	ErrMissingVariables   = errors.New("missing variables")
)
