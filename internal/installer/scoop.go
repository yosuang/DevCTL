package installer

import (
	"context"
	"devctl/pkg/executil"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ScoopInstaller implements Installer for Scoop package manager.
type ScoopInstaller struct {
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewScoopInstaller creates a new Scoop installer.
func NewScoopInstaller() *ScoopInstaller {
	return &ScoopInstaller{
		execCommand: exec.CommandContext,
	}
}

// CanAutoInstall checks if Scoop can be automatically installed.
func (s *ScoopInstaller) CanAutoInstall() (bool, error) {
	// Check if running on Windows
	if runtime.GOOS != "windows" {
		return false, errors.New("scoop is only available on Windows")
	}

	// Check if PowerShell is available
	if !executil.IsInstalled("powershell") && !executil.IsInstalled("pwsh") {
		return false, errors.New("PowerShell not found")
	}

	return true, nil
}

// GetPrerequisites returns the list of prerequisite checks.
func (s *ScoopInstaller) GetPrerequisites() []Prerequisite {
	prereqs := []Prerequisite{}

	// Check PowerShell
	psInstalled := executil.IsInstalled("powershell") || executil.IsInstalled("pwsh")
	prereqs = append(prereqs, Prerequisite{
		Name:    "PowerShell 5.1+",
		Passed:  psInstalled,
		Message: "PowerShell is required to install Scoop",
	})

	return prereqs
}

// GetInstallCommand returns the command that will be executed.
func (s *ScoopInstaller) GetInstallCommand() string {
	return "Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression"
}

// Install executes the Scoop installation process.
func (s *ScoopInstaller) Install(ctx context.Context, progress chan<- InstallProgress) error {
	// Step 1: Set execution policy
	progress <- InstallProgress{
		Stage:   "preparing",
		Message: "Setting PowerShell execution policy...",
		Percent: 10,
	}

	psCmd := "powershell"
	if executil.IsInstalled("pwsh") {
		psCmd = "pwsh"
	}

	cmd := s.execCommand(ctx, psCmd, "-Command",
		"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &InstallError{
			Manager: "scoop",
			Output:  string(output),
			Err:     fmt.Errorf("failed to set execution policy: %w", err),
		}
	}

	// Step 2: Download and execute installation script
	progress <- InstallProgress{
		Stage:   "downloading",
		Message: "Downloading Scoop installer...",
		Percent: 30,
	}

	installScript := `
		$ErrorActionPreference = 'Stop'
		try {
			Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`

	progress <- InstallProgress{
		Stage:   "installing",
		Message: "Installing Scoop (this may take 1-2 minutes)...",
		Percent: 50,
	}

	cmd = s.execCommand(ctx, psCmd, "-Command", installScript)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return &InstallError{
			Manager: "scoop",
			Output:  string(output),
			Err:     fmt.Errorf("installation failed: %w", err),
		}
	}

	// Step 3: Verify installation
	progress <- InstallProgress{
		Stage:   "verifying",
		Message: "Verifying installation...",
		Percent: 90,
	}

	path, err := s.Verify()
	if err != nil {
		return &InstallError{
			Manager: "scoop",
			Output:  string(output),
			Err:     fmt.Errorf("verification failed: %w", err),
		}
	}

	progress <- InstallProgress{
		Stage:   "complete",
		Message: fmt.Sprintf("Scoop installed successfully at: %s", path),
		Percent: 100,
	}

	return nil
}

// Verify checks if Scoop is installed and returns its path.
func (s *ScoopInstaller) Verify() (string, error) {
	path := executil.LookPath("scoop")
	if path == "" {
		return "", errors.New("scoop executable not found in PATH")
	}

	// Verify it's actually executable
	psCmd := "powershell"
	if executil.IsInstalled("pwsh") {
		psCmd = "pwsh"
	}

	cmd := s.execCommand(context.Background(), psCmd, "-Command", "scoop --version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scoop is installed but not working: %w\nOutput: %s", err, string(output))
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		return "", errors.New("scoop version check returned empty output")
	}

	return path, nil
}
