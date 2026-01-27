package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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

type PackageProgress struct {
	Name    string
	Version string
	Status  PackageStatus
	Error   error
}

type ProgressTracker struct {
	packages []PackageProgress
	current  int
	program  *tea.Program
	model    *progressModel
	output   io.Writer
}

type progressModel struct {
	packages []PackageProgress
	current  int
	spinner  spinner.Model
	quitting bool
}

type tickMsg time.Time

type finalMsg struct {
	packages []PackageProgress
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m progressModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickCmd())
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	case finalMsg:
		m.packages = msg.packages
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tickMsg:
		return m, tickCmd()
	case []PackageProgress:
		m.packages = msg
		return m, nil
	}
	return m, nil
}

func (m progressModel) View() string {
	if m.quitting {
		return ""
	}

	var builder strings.Builder

	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	skipStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	installingStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	pendingStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	for i, pkg := range m.packages {
		var line string
		pkgDisplay := pkg.Name
		if pkg.Version != "" {
			pkgDisplay = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}

		switch pkg.Status {
		case StatusSuccess:
			line = successStyle.Render("✓") + " " + pkgDisplay
		case StatusFailed:
			line = failStyle.Render("✗") + " " + pkgDisplay
			if pkg.Error != nil {
				line += failStyle.Render(fmt.Sprintf(" (%v)", pkg.Error))
			}
		case StatusSkipped:
			line = skipStyle.Render("⊘") + " " + pkgDisplay + skipStyle.Render(" (skipped)")
		case StatusInstalling:
			line = installingStyle.Render(m.spinner.View()) + " " + installingStyle.Render(pkgDisplay)
		case StatusPending:
			line = pendingStyle.Render("○") + " " + pendingStyle.Render(pkgDisplay)
		}

		builder.WriteString(line)
		if i < len(m.packages)-1 {
			builder.WriteString("\n")
		}
	}

	return builder.String() + "\n"
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

func (pt *ProgressTracker) Start() {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

	model := progressModel{
		packages: pt.packages,
		current:  pt.current,
		spinner:  s,
	}

	pt.model = &model
	pt.program = tea.NewProgram(model, tea.WithOutput(pt.output))
	go pt.program.Run()
}

func (pt *ProgressTracker) StartPackage(index int) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.current = index
	pt.packages[index].Status = StatusInstalling
	pt.updateDisplay()
}

func (pt *ProgressTracker) CompletePackage(index int) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusSuccess
	pt.updateDisplay()
}

func (pt *ProgressTracker) FailPackage(index int, err error) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusFailed
	pt.packages[index].Error = err
	pt.updateDisplay()
}

func (pt *ProgressTracker) SkipPackage(index int) {
	if index < 0 || index >= len(pt.packages) {
		return
	}

	pt.packages[index].Status = StatusSkipped
	pt.updateDisplay()
}

func (pt *ProgressTracker) Stop() {
	if pt.program != nil {
		finalPackages := append([]PackageProgress{}, pt.packages...)
		pt.program.Send(finalMsg{packages: finalPackages})
		pt.program.Wait()
	}
}

func (pt *ProgressTracker) updateDisplay() {
	if pt.program != nil {
		pt.program.Send(pt.packages)
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
