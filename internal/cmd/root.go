package cmd

import (
	"devctl/internal/logging"
	"devctl/pkg/cli"
	"devctl/pkg/cmdutil"
	"errors"
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var settings = cli.New()

func NewCmdRoot() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "devctl",
		Short:        "Development CLI",
		Long:         `Development CLI`,
		SilenceUsage: true,
	}

	settings.AddFlags(cmd.PersistentFlags())

	setupLogging()

	cmd.SetFlagErrorFunc(rootFlagErrorFunc)

	// subcommand

	return cmd, nil
}

func setupLogging() {
	logger := logging.NewLogger(func() bool { return settings.Debug })
	slog.SetDefault(logger)
}

func rootFlagErrorFunc(_ *cobra.Command, err error) error {
	if errors.Is(err, pflag.ErrHelp) {
		return err
	}
	return cmdutil.FlagErrorWrap(err)
}

type CommandError struct {
	error
	ExitCode int
}
