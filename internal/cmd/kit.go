package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"devctl/internal/config"
	"devctl/internal/kit"
	"devctl/internal/vault"
	"devctl/pkg/cmdutil"
	"devctl/pkg/executil"
	"devctl/pkg/home"
	"devctl/pkg/pkgmgr"
	"devctl/pkg/pkgmgr/brew"
	"devctl/pkg/pkgmgr/scoop"

	"github.com/spf13/cobra"
)

func NewCmdKit(cfg *config.Config) *cobra.Command {
	kitDir := filepath.Join(cfg.ConfigDir, "kit")
	vaultDir := filepath.Join(cfg.ConfigDir, "vault")

	cmd := &cobra.Command{
		Use:     "kit <command>",
		Short:   "Manage development environment",
		GroupID: "core",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdKitStatus(kitDir))
	cmd.AddCommand(newCmdKitApply(kitDir, vaultDir))
	cmd.AddCommand(newCmdKitAdd(kitDir))
	cmd.AddCommand(newCmdKitRemove(kitDir))
	cmd.AddCommand(newCmdKitTrack(kitDir))
	cmd.AddCommand(newCmdKitUntrack(kitDir))
	cmd.AddCommand(newCmdKitCompile(kitDir, vaultDir))
	cmd.AddCommand(newCmdKitSet(kitDir))
	cmd.AddCommand(newCmdKitUnset(kitDir))
	cmd.AddCommand(newCmdKitList(kitDir))

	return cmd
}

func newCmdKitStatus(kitDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show environment state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k := kit.New(kitDir)
			m, err := k.Load()
			if err != nil {
				return kitError(err)
			}

			// Package status
			var installed []pkgmgr.Package
			mgr, mgrErr := detectManager()
			if mgrErr == nil {
				installed, _ = mgr.List(cmd.Context())
			}

			groups := sortedKeys(m.Packages)
			if len(groups) > 0 {
				fmt.Fprintln(os.Stderr, "Packages:")
				for _, group := range groups {
					fmt.Fprintf(os.Stderr, "  %s:\n", group)
					statuses := kit.CheckPackageStatuses(m.Packages[group], installed)
					for _, s := range statuses {
						if s.Installed {
							ver := s.InstalledVersion
							if ver == "" {
								ver = "latest"
							}
							fmt.Fprintf(os.Stderr, "    + %s (%s)\n", s.Name, ver)
						} else {
							fmt.Fprintf(os.Stderr, "    - %s (not installed)\n", s.Name)
						}
					}
				}
			}

			// Config status
			configStatuses, err := k.ConfigStatuses()
			if err != nil {
				return err
			}
			if len(configStatuses) > 0 {
				fmt.Fprintln(os.Stderr, "Configs:")
				for _, s := range configStatuses {
					fmt.Fprintf(os.Stderr, "  %s: %s\n", s.Name, s.State)
				}
			}

			return nil
		},
	}
}

func newCmdKitApply(kitDir, vaultDir string) *cobra.Command {
	var groups []string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Install packages and compile configs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			k := kit.New(kitDir)
			m, err := k.Load()
			if err != nil {
				return kitError(err)
			}

			// Determine which groups to install
			targetGroups := groups
			if len(targetGroups) == 0 {
				targetGroups = sortedKeys(m.Packages)
			}

			// Collect packages grouped by manager
			type specWithManager struct {
				spec    pkgmgr.PackageSpec
				manager string
			}
			var all []specWithManager
			for _, g := range targetGroups {
				for _, p := range m.Packages[g] {
					all = append(all, specWithManager{
						spec: pkgmgr.PackageSpec{
							Name:    p.Name,
							Version: p.Version,
						},
						manager: p.Manager,
					})
				}
			}

			if dryRun {
				if len(all) > 0 {
					fmt.Fprintln(os.Stderr, "Would install:")
					for _, s := range all {
						label := s.spec.Name
						if s.spec.Version != "" {
							label += "@" + s.spec.Version
						}
						if s.manager != "" {
							label += " (via " + s.manager + ")"
						}
						fmt.Fprintf(os.Stderr, "  %s\n", label)
					}
				}
				configNames := sortedKeys(m.Configs)
				if len(configNames) > 0 {
					fmt.Fprintln(os.Stderr, "Would compile:")
					for _, name := range configNames {
						fmt.Fprintf(os.Stderr, "  %s -> %s\n", name, m.Configs[name].Target)
					}
				}
				return nil
			}

			// Group packages by manager for installation
			grouped := make(map[string][]pkgmgr.PackageSpec)
			for _, s := range all {
				grouped[s.manager] = append(grouped[s.manager], s.spec)
			}

			for _, mgrKey := range sortedKeys(grouped) {
				specs := grouped[mgrKey]
				var mgr pkgmgr.Manager
				var mgrErr error
				if mgrKey == "" {
					mgr, mgrErr = detectManager()
				} else {
					mgr, mgrErr = managerByType(pkgmgr.ManagerType(mgrKey))
				}
				if mgrErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: %v, skipping %d package(s)\n", mgrErr, len(specs))
					continue
				}
				mgrName := mgrKey
				if mgrName == "" {
					mgrName = "auto-detected"
				}
				fmt.Fprintf(os.Stderr, "Installing packages via %s...\n", mgrName)
				if err := mgr.InstallPackages(cmd.Context(), specs); err != nil {
					return fmt.Errorf("installing packages via %s: %w", mgrName, err)
				}
			}
			if len(grouped) > 0 {
				fmt.Fprintln(os.Stderr, "Packages installed.")
			}

			// Compile configs
			getter := secretGetter(vaultDir)
			successes, failures := k.CompileAll(cmd.Context(), getter)
			for _, name := range successes {
				fmt.Fprintf(os.Stderr, "Compiled: %s\n", name)
			}
			for _, name := range sortedKeys(failures) {
				fmt.Fprintf(os.Stderr, "Failed:   %s: %v\n", name, failures[name])
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&groups, "group", nil, "package groups to install (comma-separated)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would be done without making changes")

	return cmd
}

func newCmdKitAdd(kitDir string) *cobra.Command {
	var version string
	var group string
	var manager string

	cmd := &cobra.Command{
		Use:   "add <name[@version]>",
		Short: "Add a package to a group",
		Args:  cmdutil.ExactArgs(1, "package name is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			name, inlineVer := parsePackageArg(args[0])
			if inlineVer != "" && version != "" {
				return fmt.Errorf("ambiguous version: both inline @%s and --version %s specified", inlineVer, version)
			}
			if inlineVer != "" {
				version = inlineVer
			}

			k := kit.New(kitDir)
			if err := k.AddPackage(name, version, group, manager); err != nil {
				return kitError(err)
			}
			g := group
			if g == "" {
				g = "base"
			}
			fmt.Fprintf(os.Stderr, "Added %s to group %s\n", name, g)
			return nil
		},
	}

	cmd.Flags().StringVar(&version, "version", "", "exact version to install")
	cmd.Flags().StringVar(&group, "group", "", "package group (default: base)")
	cmd.Flags().StringVar(&manager, "manager", "", "package manager to use (e.g., scoop, brew)")

	return cmd
}

func newCmdKitRemove(kitDir string) *cobra.Command {
	var group string

	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a package from a group",
		Args:  cmdutil.ExactArgs(1, "package name is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			if err := k.RemovePackage(args[0], group); err != nil {
				return kitError(err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&group, "group", "", "package group (default: base)")

	return cmd
}

func newCmdKitTrack(kitDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "track <file-or-dir-path>",
		Short: "Track a config file or directory",
		Args:  cmdutil.ExactArgs(1, "file or directory path is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			if err := k.Track(args[0]); err != nil {
				return kitError(err)
			}
			fmt.Fprintf(os.Stderr, "Tracking %s\n", home.Short(args[0]))
			return nil
		},
	}
}

func newCmdKitUntrack(kitDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "untrack <name>",
		Short: "Untrack a config",
		Args:  cmdutil.ExactArgs(1, "config name is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			if err := k.Untrack(args[0]); err != nil {
				return kitError(err)
			}
			return nil
		},
	}
}

func newCmdKitCompile(kitDir, vaultDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "compile [<name>]",
		Short: "Compile config templates",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			getter := secretGetter(vaultDir)

			if len(args) == 1 {
				if err := k.Compile(cmd.Context(), args[0], getter); err != nil {
					return kitError(err)
				}
				fmt.Fprintf(os.Stderr, "Compiled: %s\n", args[0])
				return nil
			}

			successes, failures := k.CompileAll(cmd.Context(), getter)
			for _, name := range successes {
				fmt.Fprintf(os.Stderr, "Compiled: %s\n", name)
			}
			for _, name := range sortedKeys(failures) {
				fmt.Fprintf(os.Stderr, "Failed:   %s: %v\n", name, failures[name])
			}
			if len(failures) > 0 {
				return fmt.Errorf("%d config(s) failed to compile", len(failures))
			}
			return nil
		},
	}
}

func newCmdKitSet(kitDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "set <KEY> <VALUE>",
		Short: "Set a non-sensitive variable",
		Args:  cmdutil.ExactArgs(2, "KEY and VALUE are required"),
		RunE: func(_ *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			if err := k.SetVar(args[0], args[1]); err != nil {
				return kitError(err)
			}
			return nil
		},
	}
}

func newCmdKitUnset(kitDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "unset <KEY>",
		Short: "Remove a variable",
		Args:  cmdutil.ExactArgs(1, "KEY is required"),
		RunE: func(_ *cobra.Command, args []string) error {
			k := kit.New(kitDir)
			if err := k.UnsetVar(args[0]); err != nil {
				return kitError(err)
			}
			return nil
		},
	}
}

func newCmdKitList(kitDir string) *cobra.Command {
	var showPackages, showConfigs, showVars bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List contents",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			k := kit.New(kitDir)
			m, err := k.Load()
			if err != nil {
				return kitError(err)
			}

			showAll := !showPackages && !showConfigs && !showVars

			if showAll || showVars {
				keys, vals, err := k.ListVars()
				if err != nil {
					return err
				}
				if len(keys) > 0 {
					fmt.Fprintln(os.Stderr, "Vars:")
					for i, key := range keys {
						fmt.Fprintf(os.Stderr, "  %s=%s\n", key, vals[i])
					}
				}
			}

			if showAll || showPackages {
				groups := sortedKeys(m.Packages)
				if len(groups) > 0 {
					fmt.Fprintln(os.Stderr, "Packages:")
					for _, group := range groups {
						fmt.Fprintf(os.Stderr, "  %s:\n", group)
						for _, p := range m.Packages[group] {
							label := p.Name
							if p.Version != "" {
								label += "@" + p.Version
							}
							if p.Manager != "" {
								label += " [" + p.Manager + "]"
							}
							fmt.Fprintf(os.Stderr, "    %s\n", label)
						}
					}
				}
			}

			if showAll || showConfigs {
				configNames := sortedKeys(m.Configs)
				if len(configNames) > 0 {
					fmt.Fprintln(os.Stderr, "Configs:")
					for _, name := range configNames {
						cfg := m.Configs[name]
						fmt.Fprintf(os.Stderr, "  %s: %s -> %s\n", name, cfg.Source, cfg.Target)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showPackages, "packages", false, "list packages only")
	cmd.Flags().BoolVar(&showConfigs, "configs", false, "list configs only")
	cmd.Flags().BoolVar(&showVars, "vars", false, "list variables only")

	return cmd
}

// --- helpers ---

func secretGetter(vaultDir string) kit.SecretGetter {
	v := vault.New(vaultDir)
	return func(ctx context.Context, key string) (string, error) {
		return v.Get(ctx, key)
	}
}

func kitError(err error) error {
	switch {
	case errors.Is(err, kit.ErrManifestNotFound):
		return fmt.Errorf("kit not initialized\nRun: devctl kit set <KEY> <VALUE>  or  devctl kit add <package>  to get started")
	case errors.Is(err, kit.ErrAlreadyTracked):
		return fmt.Errorf("config already tracked")
	case errors.Is(err, kit.ErrNotTracked):
		return fmt.Errorf("config not tracked\nRun: devctl kit list --configs    (to see tracked configs)")
	case errors.Is(err, kit.ErrInvalidKeyName):
		return fmt.Errorf("invalid key — must be UPPER_SNAKE_CASE (e.g., GIT_USER_NAME)")
	case errors.Is(err, kit.ErrPackageExists):
		return fmt.Errorf("package already exists in group")
	case errors.Is(err, kit.ErrPackageNotFound):
		return fmt.Errorf("package not found in group\nRun: devctl kit list --packages    (to see packages)")
	default:
		return err
	}
}

func detectManager() (pkgmgr.Manager, error) {
	managerTypes := pkgmgr.GetCurrentPlatformManagerTypes()

	for _, mt := range managerTypes {
		switch mt {
		case pkgmgr.ManagerTypeScoop:
			if executil.IsInstalled("scoop") {
				return scoop.New(nil), nil
			}
		case pkgmgr.ManagerTypeBrew:
			if executil.IsInstalled("brew") {
				return brew.New(nil), nil
			}
		}
	}
	return nil, fmt.Errorf("no supported package manager found")
}

func parsePackageArg(arg string) (name, version string) {
	if i := strings.LastIndex(arg, "@"); i > 0 {
		return arg[:i], arg[i+1:]
	}
	return arg, ""
}

func managerByType(mt pkgmgr.ManagerType) (pkgmgr.Manager, error) {
	if !pkgmgr.IsManagerSupported(mt, pkgmgr.CurrentPlatform()) {
		return nil, fmt.Errorf("package manager %q is not supported on this platform", mt)
	}
	switch mt {
	case pkgmgr.ManagerTypeScoop:
		if !executil.IsInstalled("scoop") {
			return nil, fmt.Errorf("scoop is not installed")
		}
		return scoop.New(nil), nil
	case pkgmgr.ManagerTypeBrew:
		if !executil.IsInstalled("brew") {
			return nil, fmt.Errorf("brew is not installed")
		}
		return brew.New(nil), nil
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", mt)
	}
}

// sortedKeys returns sorted keys from a map (generic helper for map[string]T).
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
