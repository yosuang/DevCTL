package ui

import (
	"fmt"
	"io"
	"os"

	"devctl/pkg/pkgmgr"
)

// Output defines the interface for all terminal output operations.
// This abstraction allows for different output implementations (terminal, JSON, silent).
type Output interface {
	// Info prints an informational message.
	Info(msg string)

	// Success prints a success message with a checkmark.
	Success(msg string)

	// Error prints an error message with an X mark.
	Error(msg string)

	// Warning prints a warning message.
	Warning(msg string)

	// PrintDetectionResults displays package manager detection results.
	PrintDetectionResults(result DetectionResult)

	// PrintInstallProgress displays installation progress messages.
	PrintInstallProgress(stage, message string)

	// PrintManualGuide displays manual installation instructions.
	PrintManualGuide(guide ManualGuide)

	// PrintPrerequisites displays prerequisite check results.
	PrintPrerequisites(prereqs []PrerequisiteResult)

	// PrintInstallCommand displays the command that will be executed.
	PrintInstallCommand(cmd string)

	// Println prints a plain line without formatting.
	Println(msg string)

	// Printf prints a formatted message.
	Printf(format string, args ...any)

	// NewProgressTracker creates a new progress tracker for package operations.
	NewProgressTracker(packages []PackageInfo) *ProgressTracker
}

// DetectionResult represents package manager detection results.
type DetectionResult struct {
	Platform string
	Managers []ManagerStatus
}

// ManagerStatus represents the status of a single package manager.
type ManagerStatus struct {
	Name      string
	Installed bool
	Path      string
}

// ManualGuide represents manual installation instructions.
type ManualGuide struct {
	ManagerName  string
	Instructions []string
	URL          string
	VerifyCmd    string
}

// PrerequisiteResult represents a prerequisite check result.
type PrerequisiteResult struct {
	Name    string
	Passed  bool
	Message string
}

// TerminalOutput implements Output for terminal display with colors and formatting.
type TerminalOutput struct {
	Out    io.Writer
	ErrOut io.Writer
	Styles *Styles
}

// NewTerminalOutput creates a new TerminalOutput with default styles.
func NewTerminalOutput(out, errOut io.Writer) *TerminalOutput {
	return &TerminalOutput{
		Out:    out,
		ErrOut: errOut,
		Styles: NewStyles(),
	}
}

// NewDefaultOutput creates a TerminalOutput with stdout/stderr.
func NewDefaultOutput() *TerminalOutput {
	return NewTerminalOutput(os.Stdout, os.Stderr)
}

// Info prints an informational message.
func (t *TerminalOutput) Info(msg string) {
	fmt.Fprintf(t.Out, "%s %s\n", t.Styles.Info.Render(IconInfo), msg)
}

// Success prints a success message.
func (t *TerminalOutput) Success(msg string) {
	fmt.Fprintf(t.Out, "%s %s\n", t.Styles.Success.Render(IconSuccess), msg)
}

// Error prints an error message.
func (t *TerminalOutput) Error(msg string) {
	fmt.Fprintf(t.ErrOut, "%s %s\n", t.Styles.Error.Render(IconError), msg)
}

// Warning prints a warning message.
func (t *TerminalOutput) Warning(msg string) {
	fmt.Fprintf(t.Out, "%s %s\n", t.Styles.Warning.Render("⚠"), msg)
}

// PrintDetectionResults displays package manager detection results.
func (t *TerminalOutput) PrintDetectionResults(result DetectionResult) {
	fmt.Fprintf(t.Out, "\n%s\n", t.Styles.Title.Render(fmt.Sprintf("Package Manager Detection (%s)", result.Platform)))
	fmt.Fprintf(t.Out, "%s\n", Separator(50))

	for _, mgr := range result.Managers {
		if mgr.Installed {
			fmt.Fprintf(t.Out, "%s %-10s Installed at: %s\n",
				t.Styles.Success.Render(IconSuccess),
				mgr.Name,
				mgr.Path)
		} else {
			fmt.Fprintf(t.Out, "%s %-10s Not installed\n",
				t.Styles.Error.Render(IconError),
				mgr.Name)
		}
	}
}

// PrintInstallProgress displays installation progress.
func (t *TerminalOutput) PrintInstallProgress(stage, message string) {
	fmt.Fprintf(t.Out, "%s [%s] %s\n", t.Styles.Info.Render(IconInfo), stage, message)
}

// PrintManualGuide displays manual installation instructions.
func (t *TerminalOutput) PrintManualGuide(guide ManualGuide) {
	fmt.Fprintf(t.Out, "\n%s Manual Installation Guide for %s\n",
		t.Styles.Title.Render("📖"),
		guide.ManagerName)
	fmt.Fprintf(t.Out, "%s\n", Separator(50))

	for i, instruction := range guide.Instructions {
		fmt.Fprintf(t.Out, "%d. %s\n", i+1, instruction)
	}

	if guide.URL != "" {
		fmt.Fprintf(t.Out, "\nMore info: %s\n", t.Styles.Info.Render(guide.URL))
	}

	if guide.VerifyCmd != "" {
		fmt.Fprintf(t.Out, "Verify installation: %s\n", t.Styles.Info.Render(guide.VerifyCmd))
	}

	fmt.Fprintln(t.Out)
}

// PrintPrerequisites displays prerequisite check results.
func (t *TerminalOutput) PrintPrerequisites(prereqs []PrerequisiteResult) {
	if len(prereqs) == 0 {
		return
	}
	fmt.Fprintln(t.Out, "Prerequisites:")
	for _, prereq := range prereqs {
		status := t.Styles.Success.Render(IconSuccess)
		if !prereq.Passed {
			status = t.Styles.Error.Render(IconError)
		}
		fmt.Fprintf(t.Out, "  %s %s: %s\n", status, prereq.Name, prereq.Message)
	}
}

// PrintInstallCommand displays the command that will be executed.
func (t *TerminalOutput) PrintInstallCommand(cmd string) {
	fmt.Fprintf(t.Out, "\nCommand to execute:\n  %s\n\n", t.Styles.Info.Render(cmd))
}

// Println prints a plain line.
func (t *TerminalOutput) Println(msg string) {
	fmt.Fprintln(t.Out, msg)
}

// Printf prints a formatted message.
func (t *TerminalOutput) Printf(format string, args ...any) {
	fmt.Fprintf(t.Out, format, args...)
}

// NewProgressTracker creates a new progress tracker.
func (t *TerminalOutput) NewProgressTracker(packages []PackageInfo) *ProgressTracker {
	return NewProgressTracker(packages)
}

// ToManagerStatus converts a map of package manager info to ManagerStatus slice.
func ToManagerStatus(managers map[pkgmgr.ManagerType]struct {
	Type           pkgmgr.ManagerType
	Installed      bool
	ExecutablePath string
}) []ManagerStatus {
	result := make([]ManagerStatus, 0, len(managers))
	for _, mgr := range managers {
		result = append(result, ManagerStatus{
			Name:      string(mgr.Type),
			Installed: mgr.Installed,
			Path:      mgr.ExecutablePath,
		})
	}
	return result
}
