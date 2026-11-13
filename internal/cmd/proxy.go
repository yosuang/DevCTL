package cmd

import (
	"devctl/internal/proxy"

	"github.com/spf13/cobra"
)

// newProxyCmd adds start and stop.
// Neither this command nor its children set PersistentPreRun or PersistentPreRunE,
// so the root logger still starts.
func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "proxy",
		Short:        "Run the local proxy",
		GroupID:      "pair",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProxyStartCmd(), newProxyStopCmd())
	return cmd
}

func newProxyStartCmd() *cobra.Command {
	var core string
	var ticket string
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Listen on loopback",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return proxy.Start(cmd.Context(), cfg.ConfigDir, ticket, core)
		},
	}
	cmd.Flags().StringVar(&core, "core", "", "path to the local executable")
	cmd.Flags().StringVar(&ticket, "ticket", "", "ticket hash prefix")
	_ = cmd.MarkFlagRequired("core")
	return cmd
}

func newProxyStopCmd() *cobra.Command {
	var ticket string
	cmd := &cobra.Command{
		Use:          "stop",
		Short:        "Stop the local proxy",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return proxy.Stop(cmd.Context(), cfg.ConfigDir, ticket)
		},
	}
	cmd.Flags().StringVar(&ticket, "ticket", "", "ticket hash prefix")
	return cmd
}
