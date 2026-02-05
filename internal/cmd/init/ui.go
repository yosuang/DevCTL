package init

import (
	"devctl/internal/ui"
	"fmt"
)

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

// printDetectionResults displays package manager detection results.
func printDetectionResults(output ui.Output, result DetectionResult) {
	output.Printf("\n%s\n", ui.DefaultStyles.Title.Render(fmt.Sprintf("Package Manager Detection (%s)", result.Platform)))
	output.Printf("%s\n", ui.Separator(50))

	for _, mgr := range result.Managers {
		if mgr.Installed {
			output.Printf("%s %-10s Installed at: %s\n",
				ui.DefaultStyles.Success.Render(ui.IconSuccess),
				mgr.Name,
				mgr.Path)
		} else {
			output.Printf("%s %-10s Not installed\n",
				ui.DefaultStyles.Error.Render(ui.IconError),
				mgr.Name)
		}
	}
}

// printPrerequisites displays prerequisite check results.
func printPrerequisites(output ui.Output, prereqs []PrerequisiteResult) {
	if len(prereqs) == 0 {
		return
	}
	output.Println("Prerequisites:")
	for _, prereq := range prereqs {
		status := ui.DefaultStyles.Success.Render(ui.IconSuccess)
		if !prereq.Passed {
			status = ui.DefaultStyles.Error.Render(ui.IconError)
		}
		output.Printf("  %s %s: %s\n", status, prereq.Name, prereq.Message)
	}
}

// printManualGuide displays manual installation instructions.
func printManualGuide(output ui.Output, guide ManualGuide) {
	output.Printf("\n%s Manual Installation Guide for %s\n",
		ui.DefaultStyles.Title.Render("📖"),
		guide.ManagerName)

	output.Printf("%s\n", ui.Separator(50))

	for i, instruction := range guide.Instructions {
		output.Printf("%d. %s\n", i+1, instruction)
	}

	if guide.URL != "" {
		output.Printf("\nMore info: %s\n", ui.DefaultStyles.Info.Render(guide.URL))
	}

	if guide.VerifyCmd != "" {
		output.Printf("Verify installation: %s\n", ui.DefaultStyles.Info.Render(guide.VerifyCmd))
	}

	output.Println("")
}
