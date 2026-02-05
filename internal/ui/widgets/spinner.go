package widgets

import (
	"devctl/internal/ui"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type PreparationSpinner struct {
	output  ui.Output
	styles  *ui.Styles
	program *tea.Program
	model   *prepSpinnerModel
}

type prepSpinnerModel struct {
	output  ui.Output
	styles  *ui.Styles
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
	var statusIcon string
	if m.done {
		statusIcon = m.styles.Default.Render(m.styles.Success.Render(ui.IconSuccess))
	} else {
		statusIcon = m.styles.Default.Render(m.styles.Primary.Render(m.spinner.View()))
	}
	return statusIcon + " " + m.message + "\n"
}

func NewSpinner(output ui.Output) *PreparationSpinner {
	return &PreparationSpinner{
		output: output,
		styles: ui.NewStyles(),
	}
}

func (ps *PreparationSpinner) Start(message string) {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = ps.styles.Default

	model := prepSpinnerModel{
		output:  ps.output,
		styles:  ps.styles,
		spinner: s,
		message: message,
	}

	ps.model = &model
	ps.program = tea.NewProgram(model, tea.WithOutput(ps.output))
	go ps.program.Run()
}

func (ps *PreparationSpinner) Stop() {
	if ps.program != nil {
		ps.program.Send(stopMsg{})
		ps.program.Wait()
	}
}
