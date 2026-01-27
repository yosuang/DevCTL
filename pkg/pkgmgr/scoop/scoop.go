package scoop

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"devctl/pkg/pkgmgr"
)

// Config holds configuration for the Scoop package manager.
type Config struct {
	// ExecutablePath is the path to the scoop executable.
	// If empty, defaults to "scoop" (assumes it's in PATH).
	ExecutablePath string
}

// Manager implements pkgmgr.Manager for the Scoop package manager.
type Manager struct {
	execPath    string
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// New returns a new ScoopManager with the given configuration.
// If cfg is nil or ExecutablePath is empty, defaults to "scoop".
func New(cfg *Config) *Manager {
	execPath := "scoop"
	if cfg != nil && cfg.ExecutablePath != "" {
		execPath = cfg.ExecutablePath
	}
	return &Manager{
		execPath:    execPath,
		execCommand: exec.CommandContext,
	}
}

// Install installs one or more packages using scoop install.
func (m *Manager) Install(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"install"}, names...)
	cmd := m.execCommand(ctx, m.execPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "is already installed") {
			return pkgmgr.ErrAlreadyInstalled
		}
		return &pkgmgr.ExecutionError{
			Cmd:    m.execPath + " " + strings.Join(args, " "),
			Stderr: errStr,
			Err:    err,
		}
	}
	return nil
}

// Uninstall uninstalls one or more packages using scoop uninstall.
func (m *Manager) Uninstall(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"uninstall"}, names...)
	cmd := m.execCommand(ctx, m.execPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "is not installed") {
			return pkgmgr.ErrNotInstalled
		}
		return &pkgmgr.ExecutionError{
			Cmd:    m.execPath + " " + strings.Join(args, " "),
			Stderr: errStr,
			Err:    err,
		}
	}
	return nil
}

type exportOutput struct {
	Apps []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
	} `json:"apps"`
}

// List returns a list of installed packages using scoop export.
func (m *Manager) List(ctx context.Context) ([]pkgmgr.Package, error) {
	cmd := m.execCommand(ctx, m.execPath, "export")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &pkgmgr.ExecutionError{
			Cmd:    m.execPath + " export",
			Stderr: stderr.String(),
			Err:    err,
		}
	}

	var output exportOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, err
	}

	packages := make([]pkgmgr.Package, 0, len(output.Apps))
	for _, app := range output.Apps {
		packages = append(packages, pkgmgr.Package{
			Name:        app.Name,
			Version:     app.Version,
			Description: app.Description,
			Source:      "scoop",
		})
	}

	return packages, nil
}
