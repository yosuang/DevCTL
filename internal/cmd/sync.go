package cmd

import (
	"devctl/internal/config"
	devsync "devctl/internal/sync"
	"devctl/pkg/home"
	"errors"
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdSync(cfg *config.Config) *cobra.Command {
	var remoteURL string
	var commitMsg string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync config and vault via git",
		Long: heredoc.Doc(`
			First run requires -r to set the remote repository:
			  devctl sync -r <remote-url>

			Subsequent runs will reuse the configured remote (-r is ignored if already set):
			  devctl sync
		`),
		GroupID: "core",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			r := devsync.New(cfg.ConfigDir)
			if err := r.Sync(remoteURL, commitMsg); err != nil {
				return syncError(err, cfg)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&remoteURL, "remote", "r", "", "remote git repository URL (only needed on first run)")
	cmd.Flags().StringVarP(&commitMsg, "message", "m", "", "custom commit message")
	return cmd
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
	default:
		return err
	}
}
