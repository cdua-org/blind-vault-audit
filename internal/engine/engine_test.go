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
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == config.EndpointBreaches {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(testdata.FixtureBreaches)),
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	client := hibp.NewClient(nil, "")

	tempDir := t.TempDir()

	mockItems := []parser.VaultItem{
		{
			Title:   "Safe Entry",
			Domains: []string{"unique3.example.com"},
			Passwords: []parser.PasswordEntry{
				{Value: "safe", UpdatedAt: time.Now().Unix()},
			},
		},
	}
	mockProvider := &MockProvider{items: mockItems, err: nil}

	cfg := Config{
		Mode:         "breach",
		CheckAll:     false,
		Workers:      1,
		OutputDir:    t.TempDir(),
		CacheOptions: []cache.Option{cache.WithCacheDirFunc(func() (string, error) { return tempDir, nil })},
	}

	eng := New(client, mockProvider, cfg)

	err := eng.Run(context.Background(), "dummy.json")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}
