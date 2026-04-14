package cmd

import (
	"devctl/internal/build"
	"devctl/internal/config"
	"devctl/internal/logging"
	"devctl/pkg/cmdutil"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var cfg = config.Init()

func init() {
	cobra.EnableCommandSorting = false
}

func NewCmdRoot() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "devctl <command> <subcommand> [flags]",
		Short:        "Development CLI",
		Long:         `Development CLI`,
		Version:      build.FormatVersion(),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			setupLogging(cfg)
			return nil
		},
	}

	cmd.AddGroup(
		&cobra.Group{ID: "core", Title: "Core Commands:"},
		&cobra.Group{ID: "hidden", Title: ""},
	)
	cmd.SetHelpCommandGroupID("hidden")
	cmd.SetCompletionCommandGroupID("hidden")

	cfg.AddFlags(cmd.PersistentFlags())

	cmd.SetFlagErrorFunc(rootFlagErrorFunc)
	cmd.SetVersionTemplate("{{.Version}}\n")
	cmd.SetUsageTemplate(usageTemplate)

	cmd.AddCommand(NewCmdKit(cfg))
	cmd.AddCommand(NewCmdVault(cfg))
	cmd.AddCommand(NewCmdConfig(cfg))
	cmd.AddCommand(NewCmdSync(cfg))

	return cmd, nil
}

func rootFlagErrorFunc(_ *cobra.Command, err error) error {
	if errors.Is(err, pflag.ErrHelp) {
		return err
	}
	return cmdutil.FlagErrorWrap(err)
}

func setupLogging(cfg *config.Config) {
	logDir := cfg.LogDir()
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Failed to create log dir: %s, error: %v", logDir, err)
		os.Exit(1)
	}

	logfile := filepath.Join(logDir, fmt.Sprintf("%s.log", config.AppName))
	f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to open log file: %s, error: %v", logfile, err)
		os.Exit(1)
	}

	logger := logging.NewLogger(f, func() bool { return cfg.Debug })
	slog.SetDefault(logger)
}

type CommandError struct {
	error
	ExitCode int
}

var usageTemplate = heredoc.Docf(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{if .Groups}}{{range $group := .Groups}}{{if (ne $group.ID "hidden")}}

{{.Title}}{{range $.Commands}}{{if (and (eq .GroupID $group.ID) .IsAvailableCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{else}}

Available Commands:{{range .Commands}}{{if .IsAvailableCommand}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional Help Topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}


Use %[1]sdevctl <command> <subcommand> --help%[1]s for more information about a command.{{end}}
`, "`")
