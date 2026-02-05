package ui

import (
	"fmt"
	"io"
	"os"
)

// Output defines the interface for all terminal output operations.
// This abstraction allows for different output implementations (terminal, JSON, silent).
type Output interface {
	Write(p []byte) (n int, err error)

	// Info prints an informational message.
	Info(msg string)

	// Success prints a success message with a checkmark.
	Success(msg string)

	// Error prints an error message with an X mark.
	Error(msg string)

	// Warning prints a warning message.
	Warning(msg string)

	Print(msg string)

	// Printf prints a formatted message.
	Printf(format string, args ...any)

	// Println prints a plain line without formatting.
	Println(msg string)
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
		Styles: DefaultStyles,
	}
}

// NewDefaultOutput creates a TerminalOutput with stdout/stderr.
func NewDefaultOutput() *TerminalOutput {
	return NewTerminalOutput(os.Stdout, os.Stderr)
}

func (t *TerminalOutput) Write(p []byte) (n int, err error) {
	return t.Out.Write(p)
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
	fmt.Fprintf(t.Out, "%s %s\n", t.Styles.Warning.Render(IconWarning), msg)
}

func (t *TerminalOutput) Print(msg string) {
	fmt.Fprint(t.Out, msg)
}

// Printf prints a formatted message.
func (t *TerminalOutput) Printf(format string, args ...any) {
	fmt.Fprintf(t.Out, format, args...)
}

// Println prints a plain line.
func (t *TerminalOutput) Println(msg string) {
	fmt.Fprintln(t.Out, msg)
}
