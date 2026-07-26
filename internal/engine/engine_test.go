package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/hibp"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
)

type MockProvider struct {
	err   error
	items []parser.VaultItem
}

func (m *MockProvider) Parse(_ context.Context, _ string) ([]parser.VaultItem, error) {
	return m.items, m.err
}

type mockTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func TestEngine_Run(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		mockErr   error
		roundTrip func(req *http.Request) (*http.Response, error)
		name      string
		mode      string
		mockItems []parser.VaultItem
		wantErr   bool
	}{
		{
			name: "success breach mode",
			mode: config.ModeBreach,
			mockItems: []parser.VaultItem{
				{
					Title:   "Safe Entry",
					Domains: []string{"unique3.example.com"},
					Passwords: []parser.PasswordEntry{
						{Value: "safe", UpdatedAt: time.Now().Unix()},
					},
				},
			},
			mockErr: nil,
			wantErr: false,
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.FixtureBreaches)),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
		},
		{
			name:      "parse error",
			mode:      config.ModeBreach,
			mockItems: nil,
			mockErr:   errors.New("parser error"),
			wantErr:   true,
			roundTrip: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("not used")
			},
		},
		{
			name: "success mfa mode",
			mode: config.ModeMFA,
			mockItems: []parser.VaultItem{
				{
					Title:   "MFA Entry",
					Domains: []string{"unique3.example.com"},
				},
			},
			mockErr: nil,
			wantErr: false,
			roundTrip: func(req *http.Request) (*http.Response, error) {
				url := req.URL.String()
				if url == config.Endpoint2FA {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
					}, nil
				}
				if url == config.EndpointPK {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.FixturePasskeys)),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origTransport := http.DefaultTransport
			http.DefaultTransport = &mockTransport{roundTrip: tt.roundTrip}
			defer func() { http.DefaultTransport = origTransport }()

			client := hibp.NewClient(nil, "")
			mockProvider := &MockProvider{items: tt.mockItems, err: tt.mockErr}

			cfg := Config{
				Mode:         tt.mode,
				CheckAll:     false,
				Workers:      1,
				OutputDir:    t.TempDir(),
				CacheOptions: []cache.Option{cache.WithCacheDirFunc(func() (string, error) { return tempDir, nil })},
			}

			eng := New(client, mockProvider, &cfg)

			err := eng.Run(context.Background(), "dummy.json")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Expected wantErr=%v, got: %v", tt.wantErr, err)
			}
		})
	}
}
