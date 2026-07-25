package main

import (
	"os"
	"strings"
	"testing"
)

func TestMain_InvalidMode(t *testing.T) {
	exited := false
	osExit = func(code int) {
		exited = true
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	}
	defer func() { osExit = os.Exit }()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"bva-test-1", "--mode", "invalid_mode"}
	main()

	if !exited {
		t.Error("expected main to call osExit on error")
	}
}

func TestMain_MissingMode(t *testing.T) {
	exited := false
	osExit = func(code int) {
		exited = true
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
	}
	defer func() { osExit = os.Exit }()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"bva-test-2"}

	output := captureStderr(t, func() {
		main()
	})

	if !exited {
		t.Error("expected main to call osExit on missing mode")
	}
	if !strings.Contains(output, "is required") {
		t.Errorf("expected output to mention required mode, got %q", output)
	}
}

func TestMain_Version(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"bva-test-3", "--version"}

	exited := false
	osExit = func(_ int) {
		exited = true
	}
	defer func() { osExit = os.Exit }()

	main()

	if exited {
		t.Error("expected main to NOT call osExit when --version is passed")
	}
}

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		finalCheckAll bool
		wantErr       bool
	}{
		{"Valid Breach", modeBreach, true, false},
		{"Valid MFA", modeMFA, false, false},
		{"MFA with CheckAll", modeMFA, true, true},
		{"Invalid Mode", "unknown", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlags(tt.mode, tt.finalCheckAll)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		wantMode string
		args     []string
		wantErr  bool
	}{
		{"Mode from flag", modeBreach, modeBreach, []string{}, false},
		{"Mode from positional arg breach", "", modeBreach, []string{modeBreach}, false},
		{"Mode from positional arg mfa", "", modeMFA, []string{modeMFA}, false},
		{"Missing mode", "", "", []string{}, true},
		{"Invalid positional ignored", "", "", []string{"something"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := tt.mode
			err := parseMode(&mode, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mode != tt.wantMode {
				t.Errorf("parseMode() got mode = %v, want %v", mode, tt.wantMode)
			}
		})
	}
}
