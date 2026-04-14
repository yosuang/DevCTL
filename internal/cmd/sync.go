package cmd

import (
	"devctl/internal/config"
	devsync "devctl/internal/sync"
	"devctl/pkg/cmdutil"
	"devctl/pkg/home"
	"errors"
	"fmt"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

const syncRemoteURLKey = "sync.remote.url"

func NewCmdSync(cfg *config.Config) *cobra.Command {
	var commitMsg string
	var showStatus bool

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync config and vault via git",
		Long: heredoc.Doc(`
			Set the remote URL once, then run sync:
			  devctl config sync.remote.url <remote-url>
			  devctl sync
		`),
		GroupID: "core",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := devsync.New(cfg.ConfigDir)

			if showStatus {
				if cmd.Flags().Changed("message") {
					return cmdutil.FlagErrorf("--status cannot be used with -m")
				}
				result, err := r.Status()
				if err != nil {
					return syncError(err, cfg)
				}
				printStatus(cmd, result)
				return nil
			}

			remoteURL, err := resolveRemoteURL(cfg)
			if err != nil {
				return err
			}

			if err := r.Sync(remoteURL, commitMsg); err != nil {
				return syncError(err, cfg)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&commitMsg, "message", "m", "", "custom commit message")
	cmd.Flags().BoolVar(&showStatus, "status", false, "show sync status")
	return cmd
}

// resolveRemoteURL reads sync.remote.url from the config store.
// Returns empty string with no error if the repo is already initialized
// (sync will ignore the URL in that case). Returns an actionable error
// if the repo is uninitialized and the key is unset.
func resolveRemoteURL(cfg *config.Config) (string, error) {
	store := config.NewStore(cfg.ConfigFile())
	url, err := store.Get(syncRemoteURLKey)
	if err == nil {
		return url, nil
	}
	if !errors.Is(err, config.ErrKeyNotFound) {
		return "", err
	}

	// Key is unset. If the repo is already initialized, sync can proceed
	// without it (subsequent syncs don't need the URL). Otherwise, prompt.
	r := devsync.New(cfg.ConfigDir)
	if r.IsInitialized() {
		return "", nil
	}
	return "", fmt.Errorf("remote URL not configured\n  Run: devctl config sync.remote.url <URL>")
}

func printStatus(cmd *cobra.Command, result *devsync.StatusResult) {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Sync status: %s\n", result.State)

	if result.State == devsync.StatusNotInitialized {
		fmt.Fprintln(w, "  Run 'devctl config sync.remote.url <remote-url>' and then 'devctl sync' to set up sync.")
		return
	}

	if result.LastSyncedAt != nil {
		rel := relativeTime(time.Since(*result.LastSyncedAt))
		abs := result.LastSyncedAt.Format("2006-01-02 15:04")
		fmt.Fprintf(w, "  Last synced: %s (%s)\n", rel, abs)
	} else {
		fmt.Fprintln(w, "  Last synced: never")
	}

	if len(result.LocalChanges) > 0 {
		fmt.Fprintln(w, "  Local:")
		for _, c := range result.LocalChanges {
			fmt.Fprintf(w, "    %-10s%s\n", c.Type, c.Path)
		}
	}

	if result.RemoteBehind > 0 {
		noun := "commit"
		if result.RemoteBehind > 1 {
			noun = "commits"
		}
		fmt.Fprintf(w, "  Remote: %d new %s (behind)\n", result.RemoteBehind, noun)
	}
}

func relativeTime(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func syncError(err error, cfg *config.Config) error {
	switch {
	case errors.Is(err, devsync.ErrGitNotInstalled):
		return fmt.Errorf("%w\nInstall git: https://git-scm.com", err)
	case errors.Is(err, devsync.ErrRemoteRequired):
		return fmt.Errorf("%w\nRun: devctl config sync.remote.url <URL>", err)
	case errors.Is(err, devsync.ErrConflict):
		return fmt.Errorf("%w\nResolve manually:\n  cd %s\n  git pull origin main\n  # fix conflicts\n  git add . && git commit",
			err, home.Short(cfg.ConfigDir))
	case errors.Is(err, devsync.ErrFetchFailed):
		return fmt.Errorf("%w: network unavailable\n  check your internet connection and try again", err)
	default:
		return err
	}
}
