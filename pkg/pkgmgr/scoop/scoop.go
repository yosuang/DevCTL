package scoop

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"devctl/pkg/pkgmgr"
)

func init() {
	pkgmgr.Register("windows", func() pkgmgr.Manager {
		return New()
	})
}

// Manager implements pkgmgr.Manager for the Scoop package manager.
type Manager struct {
	// execCommand allows overriding exec.CommandContext for testing.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// New returns a new ScoopManager.
func New() *Manager {
	return &Manager{
		execCommand: exec.CommandContext,
	}
}

// Install installs one or more packages using scoop install.
func (m *Manager) Install(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"install"}, names...)
	cmd := m.execCommand(ctx, "scoop", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "is already installed") {
			return pkgmgr.ErrAlreadyInstalled
		}
		return &pkgmgr.ExecutionError{
			Cmd:    "scoop " + strings.Join(args, " "),
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
	cmd := m.execCommand(ctx, "scoop", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "is not installed") {
			return pkgmgr.ErrNotInstalled
		}
		return &pkgmgr.ExecutionError{
			Cmd:    "scoop " + strings.Join(args, " "),
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
	cmd := m.execCommand(ctx, "scoop", "export")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &pkgmgr.ExecutionError{
			Cmd:    "scoop export",
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
