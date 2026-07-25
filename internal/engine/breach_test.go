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

func TestRunBreach(t *testing.T) {
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

	tempDir := t.TempDir()

	cfg := Config{
		Mode:         "breach",
		CheckAll:     false,
		Workers:      2,
		OutputDir:    t.TempDir(),
		CacheOptions: []cache.Option{cache.WithCacheDirFunc(func() (string, error) { return tempDir, nil })},
	}

	client := hibp.NewClient(nil, "")

	eng := New(client, nil, cfg)

	items := []parser.VaultItem{
		{
			Title:   "Test Breach Item",
			Domains: []string{"example.net"},
			Passwords: []parser.PasswordEntry{
				{Value: "secret", UpdatedAt: time.Now().Unix()},
			},
		},
	}

	err := eng.runBreach(context.Background(), items)
	if err != nil {
		t.Fatalf("expected no error from runBreach, got %v", err)
	}
}

func TestCheckBreachedDomains(t *testing.T) {
	eng := &Engine{}

	tests := []struct {
		breaches            map[string]BreachInfo
		name                string
		itemDomains         []string
		wantBreachedDomains []string
		wantLeakedData      []string
		wantBreachTs        int64
		wantIsCompromised   bool
	}{
		{
			name: "Compromised domain",
			breaches: map[string]BreachInfo{
				"breach1.example.com": {
					Title:       "Example Breach",
					BreachDate:  1704067200,
					DataClasses: []string{DataClassPasswords},
				},
				"safe.example.org": {
					Title:       "Safe Breach",
					BreachDate:  1704067200,
					DataClasses: []string{"Email addresses"},
				},
			},
			itemDomains:         []string{"breach1.example.com", "safe.example.org", "unknown.example.net"},
			wantBreachedDomains: []string{"b1.com"},
			wantLeakedData:      []string{DataClassPasswords},
			wantBreachTs:        1704067200,
			wantIsCompromised:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := parser.VaultItem{
				Domains: tt.itemDomains,
			}

			isCompromised, breachTs, breachedDomains, leakedData := eng.checkBreachedDomains(item, tt.breaches)

			if isCompromised != tt.wantIsCompromised {
				t.Errorf("expected compromised %v, got %v", tt.wantIsCompromised, isCompromised)
			}
			if breachTs != tt.wantBreachTs {
				t.Errorf("expected timestamp %d, got %d", tt.wantBreachTs, breachTs)
			}
			if len(breachedDomains) != len(tt.wantBreachedDomains) || (len(breachedDomains) > 0 && breachedDomains[0] != tt.itemDomains[0]) {
				t.Errorf("expected breached domains %v, got %v", tt.wantBreachedDomains, breachedDomains)
			}
			if len(leakedData) != len(tt.wantLeakedData) || (len(leakedData) > 0 && leakedData[0] != tt.wantLeakedData[0]) {
				t.Errorf("expected leaked data %v, got %v", tt.wantLeakedData, leakedData)
			}
		})
	}
}
