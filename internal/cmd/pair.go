package cmd

import (
	"devctl/internal/pair"

	"github.com/spf13/cobra"
)

// newPairCmd adds receive and issue.
// Neither this command nor its children set PersistentPreRun or PersistentPreRunE,
// so the root logger still starts.
func newPairCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "pair",
		Short:        "Pair two computers",
		GroupID:      "pair",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newReceiveCmd(), newIssueCmd())
	return cmd
}

func newReceiveCmd() *cobra.Command {
	var coordinator string
	cmd := &cobra.Command{
		Use:          "receive",
		Short:        "Receive a paired proxy URI",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return pair.Receive(cmd.Context(), coordinator, pair.TerminalPrompter(), cfg.ConfigDir, "")
		},
	}
	cmd.Flags().StringVar(&coordinator, "coordinator", "", "coordinator origin (required)")
	_ = cmd.MarkFlagRequired("coordinator")
	return cmd
}

func newIssueCmd() *cobra.Command {
	var coordinator string
	cmd := &cobra.Command{
		Use:          "issue",
		Short:        "Issue a paired proxy URI",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return pair.Issue(cmd.Context(), coordinator, pair.TerminalPrompter(), cfg.ConfigDir)
		},
	}
	cmd.Flags().StringVar(&coordinator, "coordinator", "", "coordinator origin (required)")
	_ = cmd.MarkFlagRequired("coordinator")
	return cmd
}
