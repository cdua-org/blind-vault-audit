package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
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

	os.Args = []string{"bva-test-1", flagMode, "invalid_mode"}
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

	os.Args = []string{"bva-test-3", flagVersion}

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
		{"Valid Breach", config.ModeBreach, true, false},
		{"Valid MFA", config.ModeMFA, false, false},
		{"MFA with CheckAll", config.ModeMFA, true, true},
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
		{"Mode from flag", config.ModeBreach, config.ModeBreach, []string{}, false},
		{"Mode from positional arg breach", "", config.ModeBreach, []string{config.ModeBreach}, false},
		{"Mode from positional arg mfa", "", config.ModeMFA, []string{config.ModeMFA}, false},
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

func TestRun_HelpFlag(t *testing.T) {
	err := run([]string{flagHelpShort})
	if err != nil {
		t.Errorf("expected nil error for help flag, got %v", err)
	}
}

func TestRun_EngineFailure(t *testing.T) {
	err := run([]string{flagMode, config.ModeBreach, flagFileShort, "non_existent_file_12345.json"})
	if err == nil {
		t.Error("expected error for non-existent vault file, got nil")
	}
	if !strings.Contains(err.Error(), "engine run failed") {
		t.Errorf("expected engine run failed error, got %v", err)
	}
}

type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestRun_Success(t *testing.T) {
	originalHTTPClient := newHTTPClient
	defer func() { newHTTPClient = originalHTTPClient }()

	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: &mockRoundTripper{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					var body []byte
					switch req.URL.Host {
					case "2fa.directory":
						body = testdata.Fixture2FA
					case "passkeys-api.2fa.directory":
						body = testdata.FixturePasskeys
					default:
						body = []byte(`{}`)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				},
			},
		}
	}

	originalCacheDirFunc := osUserCacheDir
	defer func() { osUserCacheDir = originalCacheDirFunc }()

	cacheDir, err := os.MkdirTemp("", "bva_test_cache_*")
	if err != nil {
		t.Fatalf("failed to create cache temp dir: %v", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(cacheDir); removeErr != nil {
			t.Errorf("failed to remove cache temp dir: %v", removeErr)
		}
	}()
	osUserCacheDir = func() (string, error) {
		return cacheDir, nil
	}

	tmpFile, err := os.CreateTemp("", "test_vault_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if removeErr := os.Remove(tmpFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
			t.Errorf("failed to remove temp file: %v", removeErr)
		}
	}()

	_, err = tmpFile.Write(testdata.FixtureEnpassVault)
	if err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	if closeErr := tmpFile.Close(); closeErr != nil {
		t.Fatalf("failed to close temp file: %v", closeErr)
	}

	err = run([]string{flagMode, config.ModeMFA, flagFileShort, tmpFile.Name()})
	if err != nil {
		t.Errorf("expected nil error on success, got %v", err)
	}
}

func TestRun_ParseError(t *testing.T) {
	err := run([]string{"--unknown-flag-123"})
	if err == nil || !strings.Contains(err.Error(), "failed to parse flags") {
		t.Errorf("expected failed to parse flags error, got %v", err)
	}
}

func TestRun_VersionFlagAfterParse(t *testing.T) {
	err := run([]string{flagMode, config.ModeBreach, flagVersion})
	if err != nil {
		t.Errorf("expected nil error for version flag, got %v", err)
	}
}

func TestRun_LongFlags(t *testing.T) {
	originalHTTPClient := newHTTPClient
	defer func() { newHTTPClient = originalHTTPClient }()

	newHTTPClient = func() *http.Client {
		return &http.Client{
			Transport: &mockRoundTripper{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					var body []byte
					switch req.URL.Host {
					case "2fa.directory":
						body = testdata.Fixture2FA
					case "passkeys-api.2fa.directory":
						body = testdata.FixturePasskeys
					default:
						body = []byte(`{}`)
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				},
			},
		}
	}

	originalCacheDirFunc := osUserCacheDir
	defer func() { osUserCacheDir = originalCacheDirFunc }()

	cacheDir, err := os.MkdirTemp("", "bva_test_cache_*")
	if err != nil {
		t.Fatalf("failed to create cache temp dir: %v", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(cacheDir); removeErr != nil {
			t.Errorf("failed to remove cache temp dir: %v", removeErr)
		}
	}()
	osUserCacheDir = func() (string, error) {
		return cacheDir, nil
	}

	tmpFile, err := os.CreateTemp("", "test_vault_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if removeErr := os.Remove(tmpFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
			t.Errorf("failed to remove temp file: %v", removeErr)
		}
	}()

	_, err = tmpFile.Write(testdata.FixtureEnpassVault)
	if err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	if closeErr := tmpFile.Close(); closeErr != nil {
		t.Fatalf("failed to close temp file: %v", closeErr)
	}

	tmpDir, err := os.MkdirTemp("", "bva_test_out_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Errorf("failed to remove temp dir: %v", removeErr)
		}
	}()

	err = run([]string{flagMode, config.ModeMFA, flagFile, tmpFile.Name(), flagOutput, tmpDir})
	if err != nil {
		t.Errorf("expected nil error on success, got %v", err)
	}
}
