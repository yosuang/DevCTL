package sync

import (
	"devctl/pkg/executil"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gitignoreContent = `*
!.gitignore
!vault/
!vault/vault.age
!kit/
!kit/**
kit/.compile-state.json
`

type Repo struct {
	configDir string
}

func New(configDir string) *Repo {
	return &Repo{configDir: configDir}
}

// Sync executes the full sync flow.
// remoteURL is only required on first init (via -r flag); pass empty string after that.
// commitMsg overrides the default commit message; if empty, uses "sync: <timestamp>".
func (r *Repo) Sync(remoteURL, commitMsg string) error {
	if err := r.checkGit(); err != nil {
		return err
	}
	if err := r.ensureRepo(remoteURL); err != nil {
		return err
	}
	if err := r.fetchAndMerge(); err != nil {
		return err
	}
	if err := r.commitAndPush(commitMsg); err != nil {
		return err
	}
	return r.writeState(&SyncState{LastSyncedAt: time.Now()})
}

// IsInitialized reports whether configDir is a git repo with a remote configured.
func (r *Repo) IsInitialized() bool {
	if _, err := os.Stat(filepath.Join(r.configDir, ".git")); err != nil {
		return false
	}
	out, err := r.run("remote")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

func (r *Repo) checkGit() error {
	if !executil.IsInstalled("git") {
		return ErrGitNotInstalled
	}
	return nil
}

func (r *Repo) ensureRepo(remoteURL string) error {
	gitDir := filepath.Join(r.configDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		// Not a git repo yet — remoteURL is required.
		if remoteURL == "" {
			return ErrRemoteRequired
		}
		if _, err := r.run("init", "-b", "main"); err != nil {
			return fmt.Errorf("git init: %w", err)
		}
		if err := r.writeGitignore(); err != nil {
			return err
		}
		if _, err := r.run("remote", "add", "origin", remoteURL); err != nil {
			return fmt.Errorf("git remote add: %w", err)
		}
		return nil
	}

	// Repo exists — check if remote is configured.
	out, err := r.run("remote")
	if err != nil {
		return fmt.Errorf("git remote: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		if remoteURL == "" {
			return ErrRemoteRequired
		}
		if _, err := r.run("remote", "add", "origin", remoteURL); err != nil {
			return fmt.Errorf("git remote add: %w", err)
		}
	}

	return nil
}

func (r *Repo) writeGitignore() error {
	p := filepath.Join(r.configDir, ".gitignore")
	return os.WriteFile(p, []byte(gitignoreContent), 0644)
}

func (r *Repo) fetchAndMerge() error {
	// Fetch — if remote is empty (first push), fetch will succeed with nothing.
	if _, err := r.run("fetch", "origin"); err != nil {
		// If remote has no commits yet, fetch may fail; that's OK.
		if !strings.Contains(err.Error(), "couldn't find remote ref") {
			return fmt.Errorf("git fetch: %w", err)
		}
	}

	// Check if origin/main exists.
	if _, err := r.run("rev-parse", "--verify", "origin/main"); err != nil {
		// Remote branch doesn't exist yet — nothing to merge.
		return nil
	}

	// Check if local main exists.
	if _, err := r.run("rev-parse", "--verify", "main"); err != nil {
		// No local commits yet — nothing to merge against.
		return nil
	}

	// Check if there are remote changes to merge.
	out, err := r.run("rev-list", "HEAD..origin/main", "--count")
	if err != nil {
		return fmt.Errorf("git rev-list: %w", err)
	}
	if strings.TrimSpace(out) == "0" {
		return nil
	}

	// Merge remote changes.
	if _, err := r.run("merge", "origin/main", "--no-edit"); err != nil {
		// Conflict — abort and report.
		r.run("merge", "--abort") //nolint:errcheck
		return ErrConflict
	}
	return nil
}

func (r *Repo) commitAndPush(commitMsg string) error {
	if _, err := r.run("add", "-A"); err != nil {
		return fmt.Errorf("git add: %w", err)
	}

	// Check if there is anything to commit.
	out, err := r.run("diff", "--cached", "--stat")
	if err != nil {
		return fmt.Errorf("git diff: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		fmt.Fprintln(os.Stderr, "Already up to date")
		return nil
	}

	msg := commitMsg
	if msg == "" {
		msg = "sync: " + time.Now().Format("2006-01-02 15:04:05")
	}
	if _, err := r.run("commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	if _, err := r.run("push", "origin", "main"); err != nil {
		return fmt.Errorf("git push: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Synced successfully")
	return nil
}

func (r *Repo) run(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.configDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
