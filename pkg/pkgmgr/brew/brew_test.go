package brew

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
	case "brew", "/usr/local/bin/brew", "/opt/homebrew/bin/brew":
		switch subcmd {
		case "list":
			// Check for --json=v2 flag
			hasJSON := false
			for _, arg := range args {
				if arg == "--json=v2" {
					hasJSON = true
					break
				}
			}
			if !hasJSON {
				_, _ = fmt.Fprintf(os.Stderr, "Expected --json=v2 flag\n")
				os.Exit(1)
			}
			// brew list --json=v2 returns JSON array with formulae and casks
			fmt.Println(`[
  {
    "name": "git",
    "full_name": "git",
    "version": "2.39.0",
    "installed": [{"version": "2.39.0"}]
  },
  {
    "name": "node",
    "full_name": "node",
    "version": "18.12.0",
    "installed": [{"version": "18.12.0"}]
  },
  {
    "name": "visual-studio-code",
    "full_name": "visual-studio-code",
    "version": "1.85.0",
    "installed": [{"version": "1.85.0"}]
  }
]`)
		default:
			_, _ = fmt.Fprintf(os.Stderr, "Unknown brew subcommand %s\n", subcmd)
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

func TestBrewList_ParsesFormulaeAndCasks(t *testing.T) {
	// #given: a Manager with mocked execCommand
	mgr := &Manager{
		execPath:    "brew",
		execCommand: fakeExecCommand,
	}
	ctx := context.Background()

	// #when: calling List()
	pkgs, err := mgr.List(ctx)

	// #then: should return packages with correct data
	require.NoError(t, err)
	require.Len(t, pkgs, 3)

	// Verify first package (formula)
	require.Equal(t, "git", pkgs[0].Name)
	require.Equal(t, "2.39.0", pkgs[0].Version)
	require.Equal(t, "brew", pkgs[0].Source)

	// Verify second package (formula)
	require.Equal(t, "node", pkgs[1].Name)
	require.Equal(t, "18.12.0", pkgs[1].Version)
	require.Equal(t, "brew", pkgs[1].Source)

	// Verify third package (cask)
	require.Equal(t, "visual-studio-code", pkgs[2].Name)
	require.Equal(t, "1.85.0", pkgs[2].Version)
	require.Equal(t, "brew", pkgs[2].Source)
}

func TestBrewList_EmptyList(t *testing.T) {
	// #given: a Manager that returns empty JSON array
	mgr := &Manager{
		execPath: "brew",
		execCommand: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
			cs := []string{"-test.run=TestHelperProcessEmpty", "--", name}
			cs = append(cs, arg...)
			cmd := exec.CommandContext(ctx, os.Args[0], cs...)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "BREW_EMPTY=1")
			return cmd
		},
	}
	ctx := context.Background()

	// #when: calling List()
	pkgs, err := mgr.List(ctx)

	// #then: should return empty slice without error
	require.NoError(t, err)
	require.Empty(t, pkgs)
}

func TestHelperProcessEmpty(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" || os.Getenv("BREW_EMPTY") != "1" {
		return
	}
	defer os.Exit(0)

	fmt.Println(`[]`)
}

func TestBrewList_InvalidJSON(t *testing.T) {
	// #given: a Manager that returns invalid JSON
	mgr := &Manager{
		execPath: "brew",
		execCommand: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
			cs := []string{"-test.run=TestHelperProcessInvalidJSON", "--", name}
			cs = append(cs, arg...)
			cmd := exec.CommandContext(ctx, os.Args[0], cs...)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "BREW_INVALID=1")
			return cmd
		},
	}
	ctx := context.Background()

	// #when: calling List()
	pkgs, err := mgr.List(ctx)

	// #then: should return error
	require.Error(t, err)
	require.Nil(t, pkgs)
}

func TestHelperProcessInvalidJSON(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" || os.Getenv("BREW_INVALID") != "1" {
		return
	}
	defer os.Exit(0)

	fmt.Println(`{invalid json}`)
}

func TestBrewList_CommandError(t *testing.T) {
	// #given: a Manager where brew command fails
	mgr := &Manager{
		execPath: "brew",
		execCommand: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
			cs := []string{"-test.run=TestHelperProcessError", "--", name}
			cs = append(cs, arg...)
			cmd := exec.CommandContext(ctx, os.Args[0], cs...)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "BREW_ERROR=1")
			return cmd
		},
	}
	ctx := context.Background()

	// #when: calling List()
	pkgs, err := mgr.List(ctx)

	// #then: should return ExecutionError
	require.Error(t, err)
	require.Nil(t, pkgs)

	var execErr *pkgmgr.ExecutionError
	require.ErrorAs(t, err, &execErr)
}

func TestHelperProcessError(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" || os.Getenv("BREW_ERROR") != "1" {
		return
	}
	defer os.Exit(1)

	_, _ = fmt.Fprintf(os.Stderr, "brew: command not found\n")
}

func TestNewWithConfig(t *testing.T) {
	tests := []struct {
		name             string
		cfg              *Config
		expectedExecPath string
	}{
		{
			name:             "nil config uses default",
			cfg:              nil,
			expectedExecPath: "brew",
		},
		{
			name:             "empty config uses default",
			cfg:              &Config{},
			expectedExecPath: "brew",
		},
		{
			name: "custom executable path",
			cfg: &Config{
				ExecutablePath: "/usr/local/bin/brew",
			},
			expectedExecPath: "/usr/local/bin/brew",
		},
		{
			name: "homebrew on Apple Silicon",
			cfg: &Config{
				ExecutablePath: "/opt/homebrew/bin/brew",
			},
			expectedExecPath: "/opt/homebrew/bin/brew",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := New(tt.cfg)

			require.NotNil(t, mgr)
			require.Equal(t, tt.expectedExecPath, mgr.execPath)
			require.NotNil(t, mgr.execCommand)
		})
	}
}
