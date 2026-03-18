package logger

import (
	"io"
	"log/slog"
)

func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
