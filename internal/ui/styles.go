package ui

import "github.com/charmbracelet/lipgloss"

// Styles contains all the lipgloss styles used throughout the UI.
type Styles struct {
	Success lipgloss.Style
	Error   lipgloss.Style
	Info    lipgloss.Style
	Warning lipgloss.Style
	Title   lipgloss.Style
	Pending lipgloss.Style
}

// NewStyles creates a new Styles instance with default color scheme.
func NewStyles() *Styles {
	return &Styles{
		Success: lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true),
		Error:   lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true),
		Info:    lipgloss.NewStyle().Foreground(lipgloss.Color("12")),
		Warning: lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		Title:   lipgloss.NewStyle().Bold(true),
		Pending: lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// Icon constants for consistent UI symbols.
const (
	IconSuccess = "✓"
	IconError   = "✗"
	IconInfo    = "→"
	IconSkipped = "⊘"
	IconPending = "○"
)

// Separator returns a horizontal line of the specified length.
func Separator(length int) string {
	result := ""
	for i := 0; i < length; i++ {
		result += "─"
	}
	return result
}
