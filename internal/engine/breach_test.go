package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/hibp"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
)

func TestRunBreach(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name      string
		cacheFunc func() (string, error)
		roundTrip func(*http.Request) (*http.Response, error)
		items     []parser.VaultItem
		wantErr   bool
		force     bool
		checkAll  bool
	}{
		{
			name:      "success",
			force:     true,
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(testdata.FixtureBreaches)),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			items: []parser.VaultItem{
				{
					Title:   "Test Breach Item",
					Domains: []string{"example.net"},
					Passwords: []parser.PasswordEntry{
						{Value: "secret", UpdatedAt: time.Now().Unix()},
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "compromised",
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					breachJSON := `[
						{"Name":"TestBreach","Title":"Test Breach","Domain":"pwned.net","BreachDate":"2026-07-25","DataClasses":["Passwords"]},
						{"Title":"MissingName","Domain":"x.com","BreachDate":"2026-07-25"},
						{"Name":"InvalidDate","Title":"X","Domain":"x.com","BreachDate":"invalid-date"},
						{"Name":"NonStringClass","Title":"X","Domain":"x.com","BreachDate":"2026-07-25","DataClasses":[123,"Email"]},
						{"Name":"EmptyDomain","Title":"X","Domain":"","BreachDate":"2026-07-25"}
					]`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(breachJSON))),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			items: []parser.VaultItem{
				{
					Title:   "Pwned Item",
					Domains: []string{"pwned.net"},
					Passwords: []parser.PasswordEntry{
						{Value: "pwned_pass", UpdatedAt: 0, Order: 2, Label: "Pass1"},
						{Value: "safe_pass", UpdatedAt: time.Now().Unix(), Order: 1, Label: "Pass2"},
					},
				},
				{
					Title:   "Another Pwned Item",
					Domains: []string{"pwned.net"},
					Passwords: []parser.PasswordEntry{
						{Value: "pwned_pass", UpdatedAt: 0},
					},
				},
			},
			wantErr: false,
			force:   true,
		},
		{
			name:      "check all without passwords",
			force:     true,
			checkAll:  true,
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(`[]`))),
					}, nil
				}
				return nil, errors.New("unexpected URL")
			},
			items: []parser.VaultItem{
				{
					Title:     "No Password Item",
					Domains:   []string{"example.org"},
					Passwords: nil,
				},
			},
			wantErr: false,
		},
		{
			name:      "hibp error",
			force:     true,
			checkAll:  true,
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(`[]`))),
					}, nil
				}
				return nil, errors.New("hibp error")
			},
			items: []parser.VaultItem{
				{
					Title:     "HIBP Error Item",
					Domains:   []string{"err.example.org"},
					Passwords: []parser.PasswordEntry{{Value: "err_pass", UpdatedAt: time.Now().Unix()}},
				},
			},
			wantErr: false,
		},
		{
			name:      "hibp pwned",
			force:     true,
			checkAll:  true,
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == config.EndpointBreaches {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(`[]`))),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte("B271F2AF883C1F941092531C7BC7A7CEA74:42\n"))),
				}, nil
			},
			items: []parser.VaultItem{
				{
					Title:     "HIBP Pwned Item",
					Domains:   []string{"pwn2.example.org"},
					Passwords: []parser.PasswordEntry{{Value: "pwned_pass2", UpdatedAt: time.Now().Unix()}},
				},
			},
			wantErr: false,
		},
		{
			name: "cached",
			cacheFunc: func() (string, error) {
				d := t.TempDir()
				bvaDir := filepath.Join(d, "bva")
				if err := os.MkdirAll(bvaDir, 0o750); err != nil {
					return "", err
				}
				if err := os.WriteFile(filepath.Join(bvaDir, "breaches_v1.json"), []byte(`[]`), 0o600); err != nil {
					return "", err
				}
				return d, nil
			},
			roundTrip: func(_ *http.Request) (*http.Response, error) { return nil, errors.New("not used") },
			items: []parser.VaultItem{
				{Title: "Cached Item", Domains: []string{"example.com"}},
			},
			wantErr: false,
			force:   false,
		},
		{
			name:      "cache init error",
			cacheFunc: func() (string, error) { return "", errors.New("cache dir err") },
			roundTrip: func(_ *http.Request) (*http.Response, error) { return nil, errors.New("not used") },
			wantErr:   true,
			force:     true,
		},
		{
			name:      "fetch network error",
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(_ *http.Request) (*http.Response, error) { return nil, errors.New("fetch err") },
			wantErr:   true,
			force:     true,
		},
		{
			name:      "parse JSON error",
			cacheFunc: func() (string, error) { return tempDir, nil },
			roundTrip: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte(`{invalid-json`))),
				}, nil
			},
			wantErr: true,
			force:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origTransport := http.DefaultTransport
			http.DefaultTransport = &mockTransport{roundTrip: tt.roundTrip}
			defer func() { http.DefaultTransport = origTransport }()

			cfg := Config{
				Mode:         config.ModeBreach,
				Workers:      0,
				OutputDir:    tempDir,
				CacheOptions: []cache.Option{cache.WithCacheDirFunc(tt.cacheFunc)},
				Force:        tt.force,
				CheckAll:     tt.checkAll,
			}
			client := hibp.NewClient(nil, "")
			eng := New(client, nil, &cfg)

			err := eng.runBreach(context.Background(), tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
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
				"empty.example.com": {
					Title:       "Empty Breach",
					BreachDate:  1704067200,
					DataClasses: []string{},
				},
			},
			itemDomains:         []string{"breach1.example.com", "safe.example.org", "unknown.example.net", "empty.example.com"},
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

func TestSaveReportToFile_Errors(t *testing.T) {
	tempDir := t.TempDir()
	eng := &Engine{config: Config{}}

	fileAsDir := filepath.Join(tempDir, "file_as_dir")
	if err := os.WriteFile(fileAsDir, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.config.OutputDir = fileAsDir
	eng.saveReportToFile("test content", "breaches.txt")

	validDir := filepath.Join(tempDir, "valid_dir")
	eng.config.OutputDir = validDir
	targetFileAsDir := filepath.Join(validDir, "breaches.txt")
	if err := os.MkdirAll(targetFileAsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	eng.saveReportToFile("test content", "breaches.txt")
}
