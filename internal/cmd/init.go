package cmd

import (
	"context"
	"devctl/internal/config"
	"devctl/internal/installer"
	"devctl/internal/ui"
	"devctl/pkg/executil"
	"devctl/pkg/pkgmgr"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"
)

func NewCmdInit(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration by detecting package managers",
		Long:  `Detects installed package managers and saves their information to the configuration file.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runInit(cfg)
		},
	}

	return cmd
}

func runInit(cfg *config.Config) error {
	out := ui.NewDefaultOutput()

	currentPlatform := pkgmgr.GetCurrent()
	detectResult := detectPackageManagers(currentPlatform)
	displayDetectionResults(out, detectResult, currentPlatform)

	uninstalled := getUninstalledManagers(detectResult)
	if len(uninstalled) == 0 {
		out.Println("")
		return saveConfiguration(out, cfg, detectResult)
	}

	out.Println("")
	confirmed, err := ui.ConfirmAutoInstall(len(uninstalled))
	if err != nil {
		return fmt.Errorf("failed to get user confirmation: %w", err)
	}

	if !confirmed {
		out.Println("\nManual installation guides:")
		for _, mgr := range uninstalled {
			showManualInstallGuide(out, mgr.Type, string(currentPlatform))
		}
		out.Println("")
		return saveConfiguration(out, cfg, detectResult)
	}

	for _, mgr := range uninstalled {
		if err := attemptAutoInstall(out, mgr.Type, string(currentPlatform), cfg.Debug); err != nil {
			out.Error(fmt.Sprintf("Failed to install %s: %v", mgr.Type, err))
			continue
		}

		path := executil.LookPath(string(mgr.Type))
		if path != "" {
			detectResult[mgr.Type] = PackageManagerInfo{
				Type:           mgr.Type,
				Installed:      true,
				ExecutablePath: path,
			}
		}
	}

	out.Println("")
	return saveConfiguration(out, cfg, detectResult)
}

type PackageManagerInfo struct {
	Type           pkgmgr.ManagerType
	Installed      bool
	ExecutablePath string
}

func detectPackageManagers(p pkgmgr.Platform) map[pkgmgr.ManagerType]PackageManagerInfo {
	managers := map[pkgmgr.ManagerType]PackageManagerInfo{}
	supportedManagers := pkgmgr.GetSupportedManagers(p)

	for _, mgr := range supportedManagers {
		path := executil.LookPath(string(mgr))

		managers[mgr] = PackageManagerInfo{
			Type:           mgr,
			Installed:      path != "",
			ExecutablePath: path,
		}
	}

	return managers
}

func displayDetectionResults(out ui.Output, results map[pkgmgr.ManagerType]PackageManagerInfo, p pkgmgr.Platform) {
	managers := make([]ui.ManagerStatus, 0, len(results))
	for _, mgr := range results {
		managers = append(managers, ui.ManagerStatus{
			Name:      string(mgr.Type),
			Installed: mgr.Installed,
			Path:      mgr.ExecutablePath,
		})
	}

	out.PrintDetectionResults(ui.DetectionResult{
		Platform: string(p),
		Managers: managers,
	})
}

func getUninstalledManagers(results map[pkgmgr.ManagerType]PackageManagerInfo) []PackageManagerInfo {
	var uninstalled []PackageManagerInfo
	for _, mgr := range results {
		if !mgr.Installed {
			uninstalled = append(uninstalled, mgr)
		}
	}
	return uninstalled
}

func saveConfiguration(out ui.Output, cfg *config.Config, results map[pkgmgr.ManagerType]PackageManagerInfo) error {
	packageManagers := map[pkgmgr.ManagerType]config.PackageManagerConfig{}
	for _, p := range results {
		if p.Installed {
			packageManagers[p.Type] = config.PackageManagerConfig{
				Version:        "",
				ExecutablePath: p.ExecutablePath,
			}
		}
	}
	cfg.PackageManagers = packageManagers

	if err := config.SaveToFile(cfg, cfg.ConfigDir); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	configPath := fmt.Sprintf("%s/%s.json", cfg.ConfigDir, config.AppName)
	out.Println(fmt.Sprintf("Configuration saved to: %s", configPath))

	return nil
}

func attemptAutoInstall(out ui.Output, managerType pkgmgr.ManagerType, platformStr string, debug bool) error {
	inst := installer.GetInstaller(managerType)
	if inst == nil {
		return fmt.Errorf("no installer available for %s", managerType)
	}

	canAuto, err := inst.CanAutoInstall()
	if !canAuto {
		out.Error(fmt.Sprintf("%s: Automatic installation not available", managerType))

		failedPrereqs := getFailedPrereqs(inst.GetPrerequisites())
		if len(failedPrereqs) > 0 {
			out.PrintPrerequisites(failedPrereqs)
			out.Println("")
		}

		showGuide, _ := ui.ConfirmShowGuide()
		if showGuide {
			showManualInstallGuide(out, managerType, platformStr)
		}
		return fmt.Errorf("automatic installation not supported: %w", err)
	}

	out.Info(fmt.Sprintf("Installing %s...", managerType))

	cmd := inst.GetInstallCommand()
	slog.Debug("installer command", slog.String("manager", string(managerType)), slog.String("cmd", cmd))
	if debug {
		out.PrintInstallCommand(cmd)
	}

	failedPrereqs := getFailedPrereqs(inst.GetPrerequisites())
	if len(failedPrereqs) > 0 {
		out.Error(fmt.Sprintf("%s: prerequisites not met for automatic installation", managerType))
		out.PrintPrerequisites(failedPrereqs)
		out.Println("")
		showManualInstallGuide(out, managerType, platformStr)
		return fmt.Errorf("prerequisites not met for %s", managerType)
	}

	confirmed, err := ui.ConfirmProceed(string(managerType))
	if err != nil || !confirmed {
		return fmt.Errorf("installation cancelled by user")
	}

	progressChan := make(chan installer.InstallProgress, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- inst.Install(ctx, progressChan)
		close(progressChan)
	}()

	for progress := range progressChan {
		out.PrintInstallProgress(progress.Stage, progress.Message)
	}

	if err := <-errChan; err != nil {
		out.Error("Installation failed")
		showManualInstallGuide(out, managerType, platformStr)
		return err
	}

	out.Success(fmt.Sprintf("%s installed successfully!", managerType))
	return nil
}

func getFailedPrereqs(prereqs []installer.Prerequisite) []ui.PrerequisiteResult {
	failed := make([]ui.PrerequisiteResult, 0, len(prereqs))
	for _, prereq := range prereqs {
		if prereq.Passed {
			continue
		}
		failed = append(failed, ui.PrerequisiteResult{
			Name:    prereq.Name,
			Passed:  prereq.Passed,
			Message: prereq.Message,
		})
	}
	return failed
}

func showManualInstallGuide(out ui.Output, managerType pkgmgr.ManagerType, platformStr string) {
	guide := installer.GetInstallGuide(managerType, platformStr)
	if guide == nil {
		out.Printf("No installation guide available for %s\n", managerType)
		return
	}

	out.PrintManualGuide(ui.ManualGuide{
		ManagerName:  string(managerType),
		Instructions: guide.Instructions,
		URL:          guide.URL,
		VerifyCmd:    guide.VerifyCmd,
	})
}
