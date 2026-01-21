package logging

import (
	"context"
	"io"
	"log/slog"
)

// DebugEnabledFunc is a function type that determines if debug logging is enabled
// We use a function because we want to check the setting at log time, not when the logger is created
type DebugEnabledFunc func() bool

// DebugCheckHandler checks settings.Debug at log time
type DebugCheckHandler struct {
	handler      slog.Handler
	debugEnabled DebugEnabledFunc
}

// Enabled implements slog.Handler.Enabled
func (h *DebugCheckHandler) Enabled(_ context.Context, level slog.Level) bool {
	if level == slog.LevelDebug {
		return h.debugEnabled()
	}
	return true // Always log other levels
}

// Handle implements slog.Handler.Handle
func (h *DebugCheckHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.WithAttrs
func (h *DebugCheckHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &DebugCheckHandler{
		handler:      h.handler.WithAttrs(attrs),
		debugEnabled: h.debugEnabled,
	}
}

// WithGroup implements slog.Handler.WithGroup
func (h *DebugCheckHandler) WithGroup(name string) slog.Handler {
	return &DebugCheckHandler{
		handler:      h.handler.WithGroup(name),
		debugEnabled: h.debugEnabled,
	}
}

// NewLogger creates a new logger with dynamic debug checking
func NewLogger(w io.Writer, debugEnabled DebugEnabledFunc) *slog.Logger {
	// Create base handler that removes timestamps
	baseHandler := slog.NewTextHandler(w, &slog.HandlerOptions{
		// Always use LevelDebug here to allow all messages through
		// Our custom handler will do the filtering
		Level: slog.LevelDebug,
	})

	// Wrap with our dynamic debug-checking handler
	dynamicHandler := &DebugCheckHandler{
		handler:      baseHandler,
		debugEnabled: debugEnabled,
	}

	return slog.New(dynamicHandler)
}
