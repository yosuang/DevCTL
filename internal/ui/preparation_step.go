package ui

import (
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type PreparationSpinner struct {
	program *tea.Program
	model   *prepSpinnerModel
}

type prepSpinnerModel struct {
	spinner spinner.Model
	message string
	done    bool
}

type stopMsg struct{}

func (m prepSpinnerModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m prepSpinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case stopMsg:
		m.done = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m prepSpinnerModel) View() string {
	statusStyle := lipgloss.NewStyle().Width(2)
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	if m.done {
		statusIcon := statusStyle.Render(successStyle.Render(IconSuccess))
		return statusIcon + " " + m.message + "\n"
	}

	spinnerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	return statusStyle.Render(spinnerStyle.Render(m.spinner.View())) + " " + m.message + "\n"
}

func NewPreparationSpinner() *PreparationSpinner {
	return &PreparationSpinner{}
}

func (ps *PreparationSpinner) Start(message string) {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

	model := prepSpinnerModel{
		spinner: s,
		message: message,
	}

	ps.model = &model
	ps.program = tea.NewProgram(model, tea.WithOutput(os.Stdout))
	go ps.program.Run()
}

func (ps *PreparationSpinner) Stop() {
	if ps.program != nil {
		ps.program.Send(stopMsg{})
		ps.program.Wait()
	}
}
