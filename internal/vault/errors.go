package vault

import "errors"

var (
	ErrNotInitialized     = errors.New("vault not initialized")
	ErrAlreadyInitialized = errors.New("vault already initialized")
	ErrKeyNotFound        = errors.New("key not found")
	ErrInvalidKeyName     = errors.New("key must be UPPER_SNAKE_CASE")
)
