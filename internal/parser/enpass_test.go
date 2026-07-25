package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
