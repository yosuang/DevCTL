package installer

import "fmt"

// InstallError represents an error that occurred during installation.
type InstallError struct {
	Manager string
	Output  string
	Err     error
}

func (e *InstallError) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("failed to install %s: %v\nOutput: %s", e.Manager, e.Err, e.Output)
	}
	return fmt.Sprintf("failed to install %s: %v", e.Manager, e.Err)
}

func (e *InstallError) Unwrap() error {
	return e.Err
}
