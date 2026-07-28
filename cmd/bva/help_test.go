package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cdua-org/blind-vault-audit/internal/config"
)

func captureStderr(t *testing.T, f func()) string {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			t.Errorf("io.Copy failed: %v", err)
		}
		outC <- buf.String()
	}()

	f()

	if err := w.Close(); err != nil {
		t.Errorf("w.Close failed: %v", err)
	}
	os.Stderr = oldStderr
	return <-outC
}

func TestSetupHelp(t *testing.T) {
	tests := []struct {
		name     string
		modeVal  string
		wantText string
	}{
		{
			name:     "ModeBreach",
			modeVal:  config.ModeBreach,
			wantText: "Mode: breach - Check passwords against HIBP database",
		},
		{
			name:     "ModeMFA",
			modeVal:  config.ModeMFA,
			wantText: "Mode: mfa - Check security posture (2FA and Passkey support)",
		},
		{
			name:     "ModeUpdate",
			modeVal:  config.ModeUpdate,
			wantText: "Mode: update - Self-update bva utility to the latest release",
		},
		{
			name:     "UnknownMode",
			modeVal:  "invalid_mode",
			wantText: "Unknown mode: invalid_mode",
		},
		{
			name:     "EmptyMode",
			modeVal:  "",
			wantText: "Modes:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := tt.modeVal
			fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			setupHelp(&mode, nil, fs)
			output := captureStderr(t, func() {
				fs.Usage()
			})

			if !strings.Contains(output, tt.wantText) {
				t.Errorf("expected output to contain %q, got %q", tt.wantText, output)
			}
		})
	}
}

func TestPrintUsageExamples(t *testing.T) {
	tests := []struct {
		name     string
		modeVal  string
		wantText string
	}{
		{
			name:     "ModeBreach",
			modeVal:  config.ModeBreach,
			wantText: usageBreach,
		},
		{
			name:     "ModeMFA",
			modeVal:  config.ModeMFA,
			wantText: usageMFA,
		},
		{
			name:     "ModeUpdate",
			modeVal:  config.ModeUpdate,
			wantText: usageUpdate,
		},
		{
			name:     "UnknownMode",
			modeVal:  "bad_mode_help",
			wantText: usageMFA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStderr(t, func() {
				printUsageExamples(tt.modeVal)
			})

			if !strings.Contains(output, tt.wantText) {
				t.Errorf("expected output to contain %q", tt.wantText)
			}
		})
	}
}

func TestSetupHelp_CacheDirError(t *testing.T) {
	originalCacheDirFunc := osUserCacheDir
	defer func() { osUserCacheDir = originalCacheDirFunc }()

	osUserCacheDir = func() (string, error) {
		return "", os.ErrNotExist
	}

	mode := config.ModeBreach
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	setupHelp(&mode, nil, fs)
	output := captureStderr(t, func() {
		fs.Usage()
	})

	wantText := "unknown (could not determine user cache dir)"
	if !strings.Contains(output, wantText) {
		t.Errorf("expected output to contain %q, got %q", wantText, output)
	}
}

func TestDefaultUserCacheDir_Error(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	t.Setenv("home", "")

	dir, err := defaultUserCacheDir()
	if err == nil {
		t.Fatalf("expected error, got nil (dir: %s)", dir)
	}
	if dir != "" {
		t.Errorf("expected empty dir on error, got %s", dir)
	}
	if !strings.Contains(err.Error(), "failed to get user cache dir") {
		t.Errorf("expected wrapped error message, got: %v", err)
	}
}
