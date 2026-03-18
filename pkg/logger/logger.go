package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

func ParseLevel(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR", "FATAL":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func New(level string) *slog.Logger {
	return NewText(os.Stderr, level)
}

func NewText(w io.Writer, level string) *slog.Logger {
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: ParseLevel(level),
	})
	return slog.New(handler)
}

func Debug(format string, args ...any) {
	Debugf(slog.Default(), format, args...)
}

func Info(format string, args ...any) {
	Infof(slog.Default(), format, args...)
}

func Warn(format string, args ...any) {
	Warnf(slog.Default(), format, args...)
}

func Error(format string, args ...any) {
	Errorf(slog.Default(), format, args...)
}

func Logf(logger *slog.Logger, level slog.Level, format string, args ...any) {
	if logger == nil || !logger.Enabled(context.Background(), level) {
		return
	}
	logger.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

func Debugf(logger *slog.Logger, format string, args ...any) {
	Logf(logger, slog.LevelDebug, format, args...)
}

func Infof(logger *slog.Logger, format string, args ...any) {
	Logf(logger, slog.LevelInfo, format, args...)
}

func Warnf(logger *slog.Logger, format string, args ...any) {
	Logf(logger, slog.LevelWarn, format, args...)
}

func Errorf(logger *slog.Logger, format string, args ...any) {
	Logf(logger, slog.LevelError, format, args...)
}
