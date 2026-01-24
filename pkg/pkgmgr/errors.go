package pkgmgr

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound         = errors.New("package not found")
	ErrAlreadyInstalled = errors.New("package already installed")
	ErrNotInstalled     = errors.New("package not installed")
	ErrUnsupported      = errors.New("operation not supported")
)

type ExecutionError struct {
	Cmd    string
	Stderr string
	Err    error
}

func (e *ExecutionError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("command failed: %s: %v\nstderr: %s", e.Cmd, e.Err, e.Stderr)
	}
	return fmt.Sprintf("command failed: %s: %v", e.Cmd, e.Err)
}

func (e *ExecutionError) Unwrap() error {
	return e.Err
}
