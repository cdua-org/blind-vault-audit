package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdua-org/blind-vault-audit/internal/config"
)

func TestEnpassProvider_Parse(t *testing.T) {
	filePath := filepath.Join("..", "testdata", "enpass.json")

	provider := NewEnpassProvider()
	ctx := context.Background()

	items, err := provider.Parse(ctx, filePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	checkUptimeItem(t, items[0])
	checkClubItem(t, items[1])
}

func checkUptimeItem(t *testing.T, item VaultItem) {
	if item.Title != "Uptime" {
		t.Errorf("expected 'Uptime', got '%s'", item.Title)
	}
	expectedDomains := []string{"example.com"}
	if len(item.Domains) != len(expectedDomains) || item.Domains[0] != expectedDomains[0] {
		t.Errorf("expected domains %v, got %v", expectedDomains, item.Domains)
	}
	if len(item.Passwords) != 1 || item.Passwords[0].Value != "new_p" {
		t.Errorf("expected current password 'new_p', got %v", item.Passwords)
	}
	if item.Passwords[0].UpdatedAt != 1724023443 {
		t.Errorf("expected timestamp 1724023443, got %d", item.Passwords[0].UpdatedAt)
	}
	if !item.HasTOTP {
		t.Errorf("expected HasTOTP to be true")
	}
}

func checkClubItem(t *testing.T, item VaultItem) {
	if item.Title != "club" {
		t.Errorf("expected 'club', got '%s'", item.Title)
	}
	expectedDomains := []string{"example.net"}
	if len(item.Domains) != len(expectedDomains) || item.Domains[0] != expectedDomains[0] {
		t.Errorf("expected domains %v, got %v", expectedDomains, item.Domains)
	}
	if item.HasTOTP {
		t.Errorf("expected HasTOTP to be false")
	}
	if len(item.Passwords) != 1 || item.Passwords[0].Value != "new-pas" {
		t.Errorf("expected current password 'new-pas' and historical/duplicate to be filtered, got %v", item.Passwords)
	}
}

func TestEnpassProvider_Parse_FileNotFound(t *testing.T) {
	provider := NewEnpassProvider()
	ctx := context.Background()

	_, err := provider.Parse(ctx, "nonexistent.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestEnpassProvider_Parse_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "invalid.json")

	if err := os.WriteFile(filePath, []byte("{invalid}"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	provider := NewEnpassProvider()
	ctx := context.Background()

	_, err := provider.Parse(ctx, filePath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEnpassProvider_extractUpdatedAt(t *testing.T) {
	provider := NewEnpassProvider()

	if v := provider.extractUpdatedAt(int(12345)); v != 12345 {
		t.Errorf("expected 12345, got %d", v)
	}
	if v := provider.extractUpdatedAt(float64(54321)); v != 54321 {
		t.Errorf("expected 54321, got %d", v)
	}
}

func TestEnpassProvider_extractDomain(t *testing.T) {
	provider := NewEnpassProvider()

	tests := []struct {
		input    string
		expected string
	}{
		{"http://invalid%url", "http"},
		{"example.net:8080", "example.net"},
		{"127.0.0.1", "127.0.0.1"},
		{"http://192.168.1.1:9090", "192.168.1.1"},
		{"www.example.org", "example.org"},
	}

	for _, tt := range tests {
		if got := provider.extractDomain(tt.input); got != tt.expected {
			t.Errorf("extractDomain(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestEnpassProvider_parseItem(t *testing.T) {
	provider := NewEnpassProvider()

	tests := []struct {
		name              string
		fields            []fieldJSON
		expectedPasswords int
		expectedUpdatedAt int64
	}{
		{
			name: "deleted field",
			fields: []fieldJSON{
				{Type: config.FieldTypePassword, Value: "secret", Deleted: 1},
			},
			expectedPasswords: 0,
		},
		{
			name: "valid fields",
			fields: []fieldJSON{
				{Type: config.FieldTypePassword, Value: "pass1", ValueUpdatedAt: int(1600000000), Order: 2},
				{Type: config.FieldTypePassword, Value: "pass2", ValueUpdatedAt: int(1700000000), Order: 1},
				{Type: config.FieldTypeUsername, Value: ""},
				{Type: config.FieldTypeURL, Value: "http://invalid%url"},
			},
			expectedPasswords: 2,
			expectedUpdatedAt: 1700000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := provider.parseItem("", tt.fields)

			if item.Title != "Untitled" {
				t.Errorf("expected default Title, got %q", item.Title)
			}
			if len(item.Passwords) != tt.expectedPasswords {
				t.Errorf("expected %d passwords, got %d", tt.expectedPasswords, len(item.Passwords))
			}
			if tt.expectedPasswords > 0 && item.Passwords[0].UpdatedAt != tt.expectedUpdatedAt {
				t.Errorf("expected timestamp %d, got %d", tt.expectedUpdatedAt, item.Passwords[0].UpdatedAt)
			}
		})
	}
}
