package brew

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"

	"devctl/pkg/pkgmgr"
)

type Config struct {
	ExecutablePath string
}

type Manager struct {
	execPath    string
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

func New(cfg *Config) *Manager {
	execPath := "brew"
	if cfg != nil && cfg.ExecutablePath != "" {
		execPath = cfg.ExecutablePath
	}
	return &Manager{
		execPath:    execPath,
		execCommand: exec.CommandContext,
	}
}

type brewListItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (m *Manager) List(ctx context.Context) ([]pkgmgr.Package, error) {
	cmd := m.execCommand(ctx, m.execPath, "list", "--json=v2")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &pkgmgr.ExecutionError{
			Cmd:    m.execPath + " list --json=v2",
			Stderr: stderr.String(),
			Err:    err,
		}
	}

	var items []brewListItem
	if err := json.Unmarshal(stdout.Bytes(), &items); err != nil {
		return nil, err
	}

	packages := make([]pkgmgr.Package, 0, len(items))
	for _, item := range items {
		packages = append(packages, pkgmgr.Package{
			Name:    item.Name,
			Version: item.Version,
			Source:  "brew",
		})
	}

	return packages, nil
}

func (m *Manager) Install(_ context.Context, _ ...string) error {
	return pkgmgr.ErrUnsupported
}

func (m *Manager) Uninstall(_ context.Context, _ ...string) error {
	return pkgmgr.ErrUnsupported
}
