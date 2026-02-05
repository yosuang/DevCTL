package view

import (
	"devctl/internal/ui"
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type PackageStatus int

const (
	StatusPending PackageStatus = iota
	StatusInstalling
	StatusSuccess
	StatusFailed
	StatusSkipped
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
	output   ui.Output
}

type progressModel struct {
	styles  *ui.Styles
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
		statusIcon := m.styles.Default.Render(m.styles.Success.Render(ui.IconSuccess))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Note != "" {
			line += m.styles.Success.Render(fmt.Sprintf(" (%s)", m.pkg.Note))
		}
	case StatusFailed:
		statusIcon := m.styles.Default.Render(m.styles.Error.Render(ui.IconError))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Error != nil {
			line += m.styles.Error.Render(fmt.Sprintf(" (%v)", m.pkg.Error))
		}
	case StatusSkipped:
		statusIcon := m.styles.Default.Render(m.styles.Secondary.Render(ui.IconSkipped))
		line = statusIcon + " " + pkgDisplay
		if m.pkg.Note != "" {
			line += m.styles.Secondary.Render(fmt.Sprintf(" (%s)", m.pkg.Note))
		} else {
			line += m.styles.Secondary.Render(" (skipped)")
		}
	case StatusInstalling:
		statusIcon := m.styles.Default.Render(m.styles.Primary.Render(m.spinner.View()))
		line = statusIcon + " " + pkgDisplay
	case StatusPending:
		statusIcon := m.styles.Default.Render(m.styles.Info.Render(ui.IconPending))
		line = statusIcon + " " + pkgDisplay
	}

	return line + "\n"
}

type PackageInfo struct {
	Name    string
	Version string
}

func NewProgressTracker(output ui.Output, packages []PackageInfo) *ProgressTracker {
	pkgs := make([]PackageProgress, len(packages))
	for i, pkg := range packages {
		pkgs[i] = PackageProgress{
			Name:    pkg.Name,
			Version: pkg.Version,
			Status:  StatusPending,
		}
	}

	return &ProgressTracker{
		output:   output,
		packages: pkgs,
		current:  -1,
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

	model := progressModel{
		styles:  ui.NewStyles(),
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
