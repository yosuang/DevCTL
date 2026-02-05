package ui

import "github.com/charmbracelet/lipgloss"

// Styles contains all the lipgloss styles used throughout the UI.
type Styles struct {
	Default   lipgloss.Style
	Primary   lipgloss.Style
	Secondary lipgloss.Style
	Success   lipgloss.Style
	Info      lipgloss.Style
	Warning   lipgloss.Style
	Error     lipgloss.Style
	Title     lipgloss.Style
	Pending   lipgloss.Style
}

// NewStyles creates a new Styles instance with default color scheme.
func NewStyles() *Styles {
	return &Styles{
		Default:   lipgloss.NewStyle(),
		Primary:   lipgloss.NewStyle().Foreground(lipgloss.Color("#3B82F6")),
		Secondary: lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")),
		Success:   lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981")),
		Info:      lipgloss.NewStyle().Foreground(lipgloss.Color("#0EA5E9")),
		Warning:   lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")),
		Error:     lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")),
		Title:     lipgloss.NewStyle().Bold(true),
	}
}

// Icon constants for consistent UI symbols.
const (
	IconSuccess = "✓"
	IconWarning = "⚠"
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
