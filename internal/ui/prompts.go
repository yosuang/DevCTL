package ui

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

// ConfirmAutoInstall asks the user if they want to automatically install missing package managers.
func ConfirmAutoInstall(count int) (bool, error) {
	confirmed := true

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Found %d uninstalled package manager(s). Install automatically?", count)).
				Description("This will execute installation scripts on your system.").
				Value(&confirmed),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	return confirmed, nil
}

// ConfirmProceed asks the user to confirm before proceeding with an installation.
func ConfirmProceed(managerName string) (bool, error) {
	confirmed := true

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(fmt.Sprintf("Proceed with %s installation?", managerName)).
				Description("This will modify your system PATH and configuration.").
				Value(&confirmed),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	return confirmed, nil
}

// ConfirmShowGuide asks if the user wants to see the manual installation guide.
func ConfirmShowGuide() (bool, error) {
	confirmed := true

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Show manual installation guide?").
				Value(&confirmed),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	return confirmed, nil
}

// WaitForUserConfirmation displays a message and waits for the user to press Enter.
func WaitForUserConfirmation(message string) error {
	var dummy string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(message).
				Description("Press Enter to continue...").
				Value(&dummy).
				CharLimit(0),
		),
	)

	return form.Run()
}
