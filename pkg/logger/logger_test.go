package logger

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "DEBUG", want: "DEBUG"},
		{input: "debug", want: "DEBUG"},
		{input: "WARN", want: "WARN"},
		{input: "ERROR", want: "ERROR"},
		{input: "FATAL", want: "ERROR"},
		{input: "INFO", want: "INFO"},
		{input: "", want: "INFO"},
		{input: "unknown", want: "INFO"},
	}

	for _, tt := range tests {
		if got := ParseLevel(tt.input).String(); got != tt.want {
			t.Fatalf("ParseLevel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLogfSkipsFormattingWhenLevelDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewText(&buf, "INFO")

	var called atomic.Bool
	Logf(logger, ParseLevel("DEBUG"), "%v", stringerFunc(func() string {
		called.Store(true)
		return "expensive"
	}))

	if called.Load() {
		t.Fatal("expected disabled debug log to skip formatting")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no log output, got %q", buf.String())
	}
}

func TestLogfWritesFormattedMessageWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewText(&buf, "DEBUG")

	Debugf(logger, "hello %s", "world")

	got := buf.String()
	if !strings.Contains(got, "hello world") {
		t.Fatalf("expected formatted message in log output, got %q", got)
	}
}

type stringerFunc func() string

func (f stringerFunc) String() string {
	return f()
}
