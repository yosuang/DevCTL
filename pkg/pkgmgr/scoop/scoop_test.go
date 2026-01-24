package scoop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"devctl/pkg/pkgmgr"

	"github.com/stretchr/testify/require"
)

// TestHelperProcess isn't a real test. It's used to mock exec.Command.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for i := range args {
		if args[i] == "--" {
			args = args[i+1:]
			break
		}
	}

	if len(args) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	cmd, subcmd := args[0], ""
	if len(args) > 1 {
		subcmd = args[1]
	}

	switch cmd {
	case "scoop":
		switch subcmd {
		case "install":
			pkg := args[len(args)-1] // Simplistic: take last arg
			if pkg == "already-installed" {
				_, _ = fmt.Fprintf(os.Stderr, "'already-installed' is already installed.\n")
				os.Exit(1)
			}
			fmt.Printf("Installing '%s'...\n", pkg)
		case "uninstall":
			pkg := args[len(args)-1]
			if pkg == "not-installed" {
				_, _ = fmt.Fprintf(os.Stderr, "'not-installed' is not installed.\n")
				os.Exit(1)
			}
			fmt.Printf("Uninstalling '%s'...\n", pkg)
		case "export":
			// Scoop export returns JSON
			fmt.Println(`{"apps": [{"name": "curl", "version": "8.5.0", "description": "Command line tool and library for transferring data with URLs"}]}`)
		default:
			_, _ = fmt.Fprintf(os.Stderr, "Unknown scoop subcommand %s\n", subcmd)
			os.Exit(1)
		}
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Unknown command %s\n", cmd)
		os.Exit(1)
	}
}

// fakeExecCommand is a helper to mock exec.Command
func fakeExecCommand(ctx context.Context, name string, arg ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", name}
	cs = append(cs, arg...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	return cmd
}

func TestScoopInstall(t *testing.T) {
	mgr := &Manager{
		execCommand: fakeExecCommand,
	}
	ctx := context.Background()

	tests := []struct {
		name    string
		pkgs    []string
		wantErr error
	}{
		{
			name:    "successful install",
			pkgs:    []string{"7zip"},
			wantErr: nil,
		},
		{
			name:    "already installed",
			pkgs:    []string{"already-installed"},
			wantErr: pkgmgr.ErrAlreadyInstalled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Install(ctx, tt.pkgs...)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestScoopUninstall(t *testing.T) {
	// #given: 一个配置了 mock execCommand 的 ScoopManager
	mgr := &Manager{
		execCommand: fakeExecCommand,
	}
	ctx := context.Background()

	tests := []struct {
		name    string
		pkgs    []string
		wantErr error
	}{
		{
			name:    "successful uninstall",
			pkgs:    []string{"7zip"},
			wantErr: nil,
		},
		{
			name:    "not installed",
			pkgs:    []string{"not-installed"},
			wantErr: pkgmgr.ErrNotInstalled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #when: 执行卸载操作
			err := mgr.Uninstall(ctx, tt.pkgs...)

			// #then: 验证错误类型是否符合预期
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestScoopList(t *testing.T) {
	mgr := &Manager{
		execCommand: fakeExecCommand,
	}
	ctx := context.Background()

	pkgs, err := mgr.List(ctx)

	require.NoError(t, err)
	require.NotEmpty(t, pkgs)
	require.Equal(t, "curl", pkgs[0].Name)
	require.Equal(t, "8.5.0", pkgs[0].Version)
	require.Equal(t, "scoop", pkgs[0].Source)
}
