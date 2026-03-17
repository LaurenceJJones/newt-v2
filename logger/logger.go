package logger

import (
	"fmt"
	"log/slog"
)

func Debug(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...))
}

func Info(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}

func Warn(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func Error(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}
