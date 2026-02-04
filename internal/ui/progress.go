package ui

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type PackageStatus int

const (
	StatusPending PackageStatus = iota
	StatusInstalling
	StatusSuccess
	StatusFailed
	StatusSkipped
)

var (
	statusStyle = lipgloss.NewStyle().Width(2)
)

type PackageProgress struct {
	Name    string
	Version string
	Status  PackageStatus
	Note    string
	Error   error
}

type ProgressTracker struct {
	packages []PackageProgress
	current  int
	program  *tea.Program
	output   io.Writer
}

type progressModel struct {
	styles  *Styles
	pkg     *PackageProgress
	spinner spinner.Model
}

type progressStopMsg struct{}

func (m progressModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case progressStopMsg:
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m progressModel) View() string {
	pkgDisplay := m.pkg.Name
	if m.pkg.Version != "" {
		pkgDisplay = fmt.Sprintf("%s@%s", m.pkg.Name, m.pkg.Version)
	}

	var line string
	switch m.pkg.Status {
	case StatusSuccess:
		statusIcon := statusStyle.Render(m.styles.Success.Render(IconSuccess))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Note != "" {
			line += m.styles.Success.Render(fmt.Sprintf(" (%s)", m.pkg.Note))
		}
	case StatusFailed:
		statusIcon := statusStyle.Render(m.styles.Error.Render(IconError))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Error != nil {
			line += m.styles.Error.Render(fmt.Sprintf(" (%v)", m.pkg.Error))
		}
	case StatusSkipped:
		statusIcon := statusStyle.Render(m.styles.Secondary.Render(IconSkipped))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Note != "" {
			line += m.styles.Secondary.Render(fmt.Sprintf(" (%s)", m.pkg.Note))
		} else {
			line += m.styles.Secondary.Render(" (skipped)")
		}
	case StatusInstalling:
		statusIcon := statusStyle.Render(m.styles.Primary.Render(m.spinner.View()))
		line = statusIcon + " " + pkgDisplay
	case StatusPending:
		statusIcon := statusStyle.Render(m.styles.Info.Render("○"))
		line = statusIcon + " " + pkgDisplay
	}

	return line + "\n"
}

type PackageInfo struct {
	Name    string
	Version string
}

func NewProgressTracker(packages []PackageInfo) *ProgressTracker {
	pkgs := make([]PackageProgress, len(packages))
	for i, pkg := range packages {
		pkgs[i] = PackageProgress{
			Name:    pkg.Name,
			Version: pkg.Version,
			Status:  StatusPending,
		}
	}

	return &ProgressTracker{
		packages: pkgs,
		current:  -1,
		output:   os.Stdout,
	}
}

func (pt *ProgressTracker) StartPackage(index int) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.current = index
	pt.packages[index].Status = StatusInstalling

	// Start bubbletea for this package
	s := spinner.New()
	s.Spinner = spinner.Dot
	//s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

	model := progressModel{
		styles:  NewStyles(),
		pkg:     &pt.packages[index],
		spinner: s,
	}

	pt.program = tea.NewProgram(model, tea.WithOutput(pt.output))
	go pt.program.Run()
}

func (pt *ProgressTracker) CompletePackage(index int, note string) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusSuccess
	pt.packages[index].Note = note

	pt.stop()
}

func (pt *ProgressTracker) FailPackage(index int, err error) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusFailed
	pt.packages[index].Error = err

	pt.stop()
}

func (pt *ProgressTracker) SkipPackage(index int, note string) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusSkipped
	pt.packages[index].Note = note

	pt.stop()
}

func (pt *ProgressTracker) stop() {
	if pt.program != nil {
		pt.program.Send(progressStopMsg{})
		pt.program.Wait()
		pt.program = nil
	}
}

func (pt *ProgressTracker) GetSuccessCount() int {
	count := 0
	for _, pkg := range pt.packages {
		if pkg.Status == StatusSuccess {
			count++
		}
	}
	return count
}

func (pt *ProgressTracker) GetFailedCount() int {
	count := 0
	for _, pkg := range pt.packages {
		if pkg.Status == StatusFailed {
			count++
		}
	}
	return count
}
