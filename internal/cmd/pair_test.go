package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestPairCommandsLeaveRootLoggingHook(t *testing.T) {
	root, err := NewCmdRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pair", "receive", "issue"} {
		cmd := commandByName(root, name)
		if cmd == nil {
			t.Fatalf("missing %s", name)
		}
		if cmd.PersistentPreRun != nil || cmd.PersistentPreRunE != nil {
			t.Fatalf("%s replaced the root hook", name)
		}
	}
	if root.PersistentPreRunE == nil {
		t.Fatal("root hook")
	}

	prevDir := cfg.ConfigDir
	prevDebug := cfg.Debug
	dir := t.TempDir()
	cfg.ConfigDir = dir
	cfg.Debug = false
	t.Cleanup(func() {
		cfg.ConfigDir = prevDir
		cfg.Debug = prevDebug
	})

	var stderr bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	root.SetArgs([]string{"pair", "receive", "--coordinator", "http://example.com"})
	err = root.Execute()
	if err == nil || !strings.Contains(err.Error(), "bad_request:") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "example.com") || strings.Contains(stderr.String(), "example.com") {
		t.Fatal("coordinator url was written")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "logs", "devctl.log")); statErr != nil {
		t.Fatal("root logging did not run")
	}
}

func TestIssueRequiresCoordinator(t *testing.T) {
	root, err := NewCmdRoot()
	if err != nil {
		t.Fatal(err)
	}
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"pair", "issue"})
	err = root.Execute()
	if err == nil || !strings.Contains(err.Error(), "coordinator") {
		t.Fatalf("err %v", err)
	}
}

func commandByName(root *cobra.Command, name string) *cobra.Command {
	if root.Name() == name {
		return root
	}
	for _, child := range root.Commands() {
		if found := commandByName(child, name); found != nil {
			return found
		}
	}
	return nil
}
