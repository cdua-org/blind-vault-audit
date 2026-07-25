package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
)

func TestRunMFA(t *testing.T) {
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

	cfg := Config{
		Mode:         "mfa",
		CheckAll:     false,
		Workers:      1,
		OutputDir:    t.TempDir(),
		CacheOptions: []cache.Option{cache.WithCacheDirFunc(func() (string, error) { return tempDir, nil })},
	}

	eng := New(nil, nil, cfg)

	items := []parser.VaultItem{
		{
			Title:   "Test MFA Item",
			Domains: []string{"example.com"},
			Passwords: []parser.PasswordEntry{
				{Value: "secret", UpdatedAt: time.Now().Unix()},
			},
		},
	}

	err := eng.runMFA(context.Background(), items)
	if err != nil {
		t.Fatalf("expected no error from runMFA, got %v", err)
	}
}

func TestEvaluateAllItems(t *testing.T) {
	eng := &Engine{}

	tests := []struct {
		tfaDB        map[string]SecurityInfo
		pkDB         map[string]SecurityInfo
		name         string
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
			tfaDB: map[string]SecurityInfo{
				"mfa1.example.com": {
					Documentation: "https://example.com/2fa",
				},
			},
			pkDB: map[string]SecurityInfo{
				"mfa2.example.com": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var processed atomic.Int32
			list2FA, passkeyList := eng.evaluateAllItems(tt.items, tt.tfaDB, tt.pkDB, &processed)

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
