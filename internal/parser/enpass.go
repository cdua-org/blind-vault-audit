package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// EnpassProvider implements the Provider interface for Enpass JSON exports.
type EnpassProvider struct{}

// NewEnpassProvider creates a new EnpassProvider.
func NewEnpassProvider() *EnpassProvider {
	return &EnpassProvider{}
}

// Parse reads an Enpass JSON file and extracts VaultItems.
func (p *EnpassProvider) Parse(_ context.Context, filePath string) ([]VaultItem, error) {
	fileData, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var vault struct {
		Items []struct {
			Title  string      `json:"title"`
			Fields []fieldJSON `json:"fields"`
		} `json:"items"`
	}

	if err := json.Unmarshal(fileData, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var results []VaultItem
	for _, item := range vault.Items {
		vaultItem := p.parseItem(item.Title, item.Fields)
		if len(vaultItem.Domains) > 0 || len(vaultItem.Passwords) > 0 {
			results = append(results, vaultItem)
		}
	}

	return results, nil
}

type fieldJSON struct {
	ValueUpdatedAt any    `json:"value_updated_at"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	History        []struct {
		Value string `json:"value"`
	} `json:"history"`
}

func (p *EnpassProvider) parseItem(title string, fields []fieldJSON) VaultItem {
	vaultItem := VaultItem{
		Title: title,
	}

	if vaultItem.Title == "" {
		vaultItem.Title = "Untitled"
	}

	domainSet := make(map[string]struct{})

	historySet := make(map[string]struct{})
	for _, field := range fields {
		if field.Type == "password" {
			for _, h := range field.History {
				if h.Value != "" {
					historySet[h.Value] = struct{}{}
				}
			}
		}
	}

	for _, field := range fields {
		val := field.Value
		if val == "" {
			continue
		}

		switch field.Type {
		case "url":
			domain := p.extractDomain(strings.TrimSpace(val))
			if domain != "" {
				domainSet[domain] = struct{}{}
			}
		case "password":
			if _, isOld := historySet[val]; isOld {
				continue
			}
			updatedAt := p.extractUpdatedAt(field.ValueUpdatedAt)
			vaultItem.Passwords = append(vaultItem.Passwords, PasswordEntry{
				Value:     val,
				UpdatedAt: updatedAt,
			})
		case "totp":
			vaultItem.HasTOTP = true
		}
	}

	for d := range domainSet {
		vaultItem.Domains = append(vaultItem.Domains, d)
	}

	return vaultItem
}

func (p *EnpassProvider) extractDomain(val string) string {
	valLower := strings.ToLower(val)
	var host string
	if strings.HasPrefix(valLower, "http://") || strings.HasPrefix(valLower, "https://") {
		u, parseErr := url.Parse(valLower)
		if parseErr == nil {
			host = u.Host
		} else {
			host = valLower
		}
	} else {
		host = valLower
	}

	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	host = strings.TrimPrefix(host, "www.")

	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil && root != "" {
		return root
	}
	return host
}

func (p *EnpassProvider) extractUpdatedAt(val any) int64 {
	var updatedAt int64
	switch v := val.(type) {
	case float64:
		updatedAt = int64(v)
	case int:
		updatedAt = int64(v)
	}
	return updatedAt
}
