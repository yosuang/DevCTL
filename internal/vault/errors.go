package vault

import "errors"

var (
	ErrIdentityNotFound = errors.New("identity not found")
	ErrVaultNotFound    = errors.New("vault not found")
	ErrVaultExists      = errors.New("vault already exists")
	ErrKeyNotFound      = errors.New("key not found")
	ErrInvalidKeyName   = errors.New("key must be UPPER_SNAKE_CASE")
)
