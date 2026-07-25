// Package engine provides the core audit logic for checking password vaults.
package engine

import (
	"context"
	"fmt"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/cli/spinner"
	"github.com/cdua-org/blind-vault-audit/internal/hibp"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
)

// Config holds the configuration for the audit engine.
type Config struct {
	Mode         string
	OutputDir    string
	CacheOptions []cache.Option
	Workers      int
	CheckAll     bool
	Force        bool
}

// Engine orchestrates the breach audit process.
type Engine struct {
	hibpClient *hibp.Client
	parser     parser.Provider
	config     Config
}

// New creates a new Engine instance.
func New(hibpClient *hibp.Client, provider parser.Provider, config Config) *Engine {
	return &Engine{
		hibpClient: hibpClient,
		parser:     provider,
		config:     config,
	}
}

// Run executes the audit engine based on the configured mode.
func (e *Engine) Run(ctx context.Context, vaultPath string) error {
	stopParse := spinner.Start(ctx, "Parsing vault...", nil, 0)
	items, err := e.parser.Parse(ctx, vaultPath)
	stopParse()
	if err != nil {
		return fmt.Errorf("failed to parse vault: %w", err)
	}

	if e.config.Mode == "mfa" {
		return e.runMFA(ctx, items)
	}
	return e.runBreach(ctx, items)
}
