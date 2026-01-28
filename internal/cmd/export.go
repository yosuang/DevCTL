package cmd

import (
	"devctl/internal/config"
	"devctl/internal/formats"
	"devctl/pkg/cmdutil"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

func NewCmdExport(cfg *config.Config) *cobra.Command {
	var outDir string
	var outFile string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export installed packages from config",
		Long:  `Export installed packages from the configuration file to a JSON file that can be used with 'devctl import'.`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runExport(cfg, outDir, outFile)
		},
	}

	cmd.Flags().StringVarP(&outDir, "dir", "d", "", "output directory")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "output file path")

	return cmd
}

func runExport(cfg *config.Config, outDir, outFile string) error {
	if cfg == nil {
		return fmt.Errorf("missing config")
	}

	if outDir != "" && outFile != "" {
		return cmdutil.FlagErrorf("cannot use -d and -o together")
	}

	exportPath := outFile
	if exportPath == "" {
		fileName := fmt.Sprintf("%s-export.%s.json", config.AppName, runtime.GOOS)
		dir := outDir
		if dir == "" {
			dir = "."
		}
		exportPath = filepath.Join(dir, fileName)
	}

	pkgs := make([]formats.PackageFormat, 0, len(cfg.Packages))
	for _, p := range cfg.Packages {
		pf := formats.FromConfig(p)
		if pf.Name == "" || pf.Version == "" || pf.InstalledBy == "" {
			continue
		}
		pkgs = append(pkgs, pf)
	}

	if len(pkgs) == 0 {
		fmt.Println("No valid packages to export")
		return nil
	}

	exportFile := &formats.ManifestFile{
		Platform: runtime.GOOS,
		Packages: pkgs,
	}

	if err := formats.SaveManifestFile(exportPath, exportFile); err != nil {
		return err
	}

	fmt.Printf("Exported to: %s\n", exportPath)
	return nil
}
