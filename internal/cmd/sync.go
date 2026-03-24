package cmd

import (
	"devctl/internal/config"
	devsync "devctl/internal/sync"
	"devctl/pkg/cmdutil"
	"devctl/pkg/home"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func NewCmdSync(cfg *config.Config) *cobra.Command {
	var remoteURL string
	var commitMsg string
	var showStatus bool

	cmd := &cobra.Command{
		Use:     "sync",
		Short:   "Sync config and vault via git",
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

			if err := r.Sync(remoteURL, commitMsg); err != nil {
				return syncError(err, cfg)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&remoteURL, "remote", "r", "", "remote git repository URL")
	cmd.Flags().StringVarP(&commitMsg, "message", "m", "", "custom commit message")
	cmd.Flags().BoolVar(&showStatus, "status", false, "show sync status")
	return cmd
}

func printStatus(cmd *cobra.Command, result *devsync.StatusResult) {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Sync status: %s\n", result.State)

	if result.State == devsync.StatusNotInitialized {
		fmt.Fprintln(w, "  Run 'devctl sync -r <remote-url>' to set up sync.")
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
		return fmt.Errorf("%w\nRun: `devctl sync -r <remote-url>`", err)
	case errors.Is(err, devsync.ErrConflict):
		return fmt.Errorf("%w\nResolve manually:\n  cd %s\n  git pull origin main\n  # fix conflicts\n  git add . && git commit",
			err, home.Short(cfg.ConfigDir))
	case errors.Is(err, devsync.ErrFetchFailed):
		return fmt.Errorf("%w: network unavailable\n  check your internet connection and try again", err)
	default:
		return err
	}
}
