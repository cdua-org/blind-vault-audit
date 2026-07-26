package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
)

func TestRunMFA(t *testing.T) {
	tests := []struct {
		cacheFunc   func() (string, error)
		roundTrip   func(req *http.Request) (*http.Response, error)
		name        string
		errContains string
		items       []parser.VaultItem
		wantErr     bool
	}{
		{
			name: "success with findings",
			items: []parser.VaultItem{
				{
					Title:   "Example",
					Domains: []string{"example.com"},
				},
			},
			cacheFunc: func() (string, error) { return t.TempDir(), nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				urlStr := req.URL.String()
				if urlStr == config.Endpoint2FA {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
					}, nil
				}
				if urlStr == config.EndpointPK {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.FixturePasskeys)),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			wantErr: false,
		},
		{
			name:        "cache init error",
			items:       []parser.VaultItem{},
			cacheFunc:   func() (string, error) { return "", errors.New("cache dir error") },
			roundTrip:   nil,
			wantErr:     true,
			errContains: "failed to init cache manager",
		},
		{
			name:      "fetch 2fa network error",
			items:     []parser.VaultItem{},
			cacheFunc: func() (string, error) { return t.TempDir(), nil },
			roundTrip: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network down")
			},
			wantErr:     true,
			errContains: "failed to fetch 2FA data",
		},
		{
			name:      "fetch passkeys network error",
			items:     []parser.VaultItem{},
			cacheFunc: func() (string, error) { return t.TempDir(), nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				urlStr := req.URL.String()
				if urlStr == config.Endpoint2FA {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
					}, nil
				}
				if urlStr == config.EndpointPK {
					return nil, errors.New("network down")
				}
				return nil, errors.New("unexpected")
			},
			wantErr:     true,
			errContains: "failed to fetch passkeys data",
		},
		{
			name:      "parse 2FA error",
			items:     []parser.VaultItem{},
			cacheFunc: func() (string, error) { return t.TempDir(), nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				urlStr := req.URL.String()
				if urlStr == config.Endpoint2FA {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(`invalid json`))),
					}, nil
				}
				if urlStr == config.EndpointPK {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.FixturePasskeys)),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			wantErr:     true,
			errContains: "failed to parse 2FA",
		},
		{
			name:      "parse passkeys error",
			items:     []parser.VaultItem{},
			cacheFunc: func() (string, error) { return t.TempDir(), nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				urlStr := req.URL.String()
				if urlStr == config.Endpoint2FA {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
					}, nil
				}
				if urlStr == config.EndpointPK {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(`invalid json`))),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			wantErr:     true,
			errContains: "failed to parse passkeys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origTransport := http.DefaultTransport
			http.DefaultTransport = &mockTransport{roundTrip: tt.roundTrip}
			defer func() { http.DefaultTransport = origTransport }()

			cfg := Config{
				Mode:         config.ModeMFA,
				CheckAll:     false,
				Workers:      1,
				OutputDir:    t.TempDir(),
				CacheOptions: []cache.Option{cache.WithCacheDirFunc(tt.cacheFunc)},
			}

			eng := New(nil, nil, &cfg)
			err := eng.runMFA(context.Background(), tt.items)

			if (err != nil) != tt.wantErr {
				t.Fatalf("expected wantErr=%v, got error=%v", tt.wantErr, err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

func TestRunMFA_FileErrors(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			urlStr := req.URL.String()
			if urlStr == config.Endpoint2FA {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
				}, nil
			}
			if urlStr == config.EndpointPK {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(testdata.FixturePasskeys)),
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()

	badDirPath := tempDir + "/file_as_dir"
	err := os.WriteFile(badDirPath, []byte("test"), 0o600)
	if err != nil {
		t.Fatalf("failed to setup bad dir: %v", err)
	}

	cfg := Config{
		Mode:         config.ModeMFA,
		OutputDir:    badDirPath,
		CacheOptions: []cache.Option{cache.WithCacheDirFunc(func() (string, error) { return tempDir, nil })},
	}
	eng := New(nil, nil, &cfg)
	err = eng.runMFA(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	validDir := tempDir + "/valid_dir"
	err = os.MkdirAll(validDir+"/mfa.txt", 0o750)
	if err != nil {
		t.Fatalf("failed to setup valid dir: %v", err)
	}

	cfg.OutputDir = validDir
	eng = New(nil, nil, &cfg)
	err = eng.runMFA(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestEvaluateAllItems(t *testing.T) {
	eng := &Engine{}

	tests := []struct {
		name         string
		db2FA        map[string]SecurityInfo
		dbPK         map[string]SecurityInfo
		want2FAItem  string
		wantPkItem   string
		items        []parser.VaultItem
		want2FACount int
		wantPkCount  int
	}{
		{
			name:         "MFA and Passkey found",
			want2FAItem:  "Example",
			wantPkItem:   "Login",
			want2FACount: 1,
			wantPkCount:  0,
			items: []parser.VaultItem{
				{
					Title:   "Example Login",
					Domains: []string{"mfa1.example.com"},
				},
				{
					Title:   "Unknown Login",
					Domains: []string{"unknown.example.net"},
				},
			},
			db2FA: map[string]SecurityInfo{
				"mfa1.example.com": {
					Documentation: "https://example.com/2fa",
				},
			},
			dbPK: map[string]SecurityInfo{
				"mfa2.example.com": {},
			},
		},
		{
			name:         "HasTOTP is true ignores 2FA",
			want2FACount: 0,
			items: []parser.VaultItem{
				{
					Title:   "Example Login with TOTP",
					Domains: []string{"mfa3.example.com"},
					HasTOTP: true,
				},
			},
			db2FA: map[string]SecurityInfo{
				"mfa3.example.com": {
					Documentation: "https://example.com/2fa-3",
				},
			},
		},
		{
			name:        "HasTOTP is true evaluates Passkey",
			wantPkCount: 1,
			items: []parser.VaultItem{
				{
					Title:   "Example Login with TOTP for Passkeys",
					Domains: []string{"mfa4.example.com"},
					HasTOTP: true,
				},
			},
			dbPK: map[string]SecurityInfo{
				"mfa4.example.com": {
					Documentation: "https://example.com/passkeys-4",
				},
			},
		},
		{
			name:         "Deduplication 2FA",
			want2FACount: 1,
			items: []parser.VaultItem{
				{
					Title:   "Example Login multiple domains",
					Domains: []string{"mfa5.example.com", "mfa6.example.com"},
				},
			},
			db2FA: map[string]SecurityInfo{
				"mfa5.example.com": {
					Documentation: "https://example.com/2fa-5",
					Notes:         "note1",
				},
				"mfa6.example.com": {
					Documentation: "https://example.com/2fa-5",
					Notes:         "note1",
				},
			},
		},
		{
			name:        "Deduplication PK",
			wantPkCount: 1,
			items: []parser.VaultItem{
				{
					Title:   "Example Login multiple domains PK",
					Domains: []string{"mfa7.example.com", "mfa8.example.com"},
				},
			},
			dbPK: map[string]SecurityInfo{
				"mfa7.example.com": {
					Documentation: "https://example.com/pk-7",
					Notes:         "note2",
				},
				"mfa8.example.com": {
					Documentation: "https://example.com/pk-7",
					Notes:         "note2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processed atomic.Int32
			list2FA, passkeyList := eng.evaluateAllItems(tt.items, tt.db2FA, tt.dbPK, &processed)

			if len(list2FA) != tt.want2FACount {
				t.Fatalf("expected %d item with 2FA info, got %d", tt.want2FACount, len(list2FA))
			}
			if tt.want2FACount > 0 && !strings.Contains(list2FA[0], tt.want2FAItem) {
				t.Errorf("expected 2FA info for %s, got %q", tt.want2FAItem, list2FA[0])
			}

			if len(passkeyList) != tt.wantPkCount {
				t.Fatalf("expected %d item with Passkey info, got %d", tt.wantPkCount, len(passkeyList))
			}
			if tt.wantPkCount > 0 && !strings.Contains(passkeyList[0], tt.wantPkItem) {
				t.Errorf("expected Passkey info for %s, got %q", tt.wantPkItem, passkeyList[0])
			}
			if int(processed.Load()) != len(tt.items) {
				t.Errorf("expected %d processed items, got %d", len(tt.items), processed.Load())
			}
		})
	}
}

func TestParse2FAData(t *testing.T) {
	eng := &Engine{}

	t.Run("parse_error", func(t *testing.T) {
		_, err := eng.parse2FAData([]byte(`invalid json`))
		if err == nil {
			t.Error("expected error for invalid json, got nil")
		}
	})

	t.Run("edge_cases", func(t *testing.T) {
		data := []byte(`[
			[],
			["name"],
			["name", "not an object"],
			["name", {"domain": 123, "tfa": ["totp"]}],
			["name", {"domain": "d1.com", "tfa": "not array"}],
			["name", {"domain": "d2.com", "tfa": [123]}],
			["name", {"domain": "d3.com", "tfa": ["totp"], "documentation": 123}],
			["name", {"domain": "d4.com", "tfa": ["sms"]}],
			["name", {"domain": "d5.com", "tfa": ["totp"], "notes": 123}]
		]`)
		res, err := eng.parse2FAData(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(res) != 2 {
			t.Errorf("expected 2 parsed entries, got %d", len(res))
		}

		if info, ok := res["d3.com"]; !ok || info.Documentation != "" {
			t.Errorf("expected d3.com to be parsed without documentation, got: %+v", info)
		}

		if info, ok := res["d5.com"]; !ok || info.Notes != "" {
			t.Errorf("expected d5.com to be parsed without notes, got: %+v", info)
		}
	})
}

func TestParsePasskeysData(t *testing.T) {
	eng := &Engine{}

	t.Run("parse_error", func(t *testing.T) {
		_, err := eng.parsePasskeysData([]byte(`invalid json`))
		if err == nil {
			t.Error("expected error for invalid json, got nil")
		}
	})

	t.Run("edge_cases", func(t *testing.T) {
		data := []byte(`{
			"d1.com": 123,
			"d2.com": {"documentation": "no passwordless field"},
			"d3.com": {"passwordless": 123},
			"d4.com": {"passwordless": "allowed", "documentation": 123},
			"d5.com": {"passwordless": "allowed", "notes": 123},
			"d6.com": {"passwordless": "allowed", "notes": "Some valid notes"}
		}`)
		res, err := eng.parsePasskeysData(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(res) != 3 {
			t.Errorf("expected 3 parsed entries, got %d", len(res))
		}

		if info, ok := res["d4.com"]; !ok || info.Documentation != "" {
			t.Errorf("expected d4.com to be parsed without documentation, got: %+v", info)
		}

		if info, ok := res["d5.com"]; !ok || info.Notes != "" {
			t.Errorf("expected d5.com to be parsed without notes, got: %+v", info)
		}

		if info, ok := res["d6.com"]; !ok || info.Notes != "Some valid notes" {
			t.Errorf("expected d6.com to have valid notes, got: %+v", info)
		}
	})
}
