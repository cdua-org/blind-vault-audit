// Package main provides the entry point for the Blind Vault Audit CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/cdua-org/blind-vault-audit/internal/engine"
	"github.com/cdua-org/blind-vault-audit/internal/hibp"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
)

var (
	Version = "dev"
	osExit  = os.Exit
)

const (
	flagMode         = "--mode"
	flagFile         = "--file"
	flagFileShort    = "-f"
	flagAll          = "--all"
	flagAllShort     = "-a"
	flagWorkers      = "--workers"
	flagWorkersShort = "-w"
	flagOutput       = "--output"
	flagOutputShort  = "-o"
	flagForce        = "--force"
	flagVersion      = "--version"
	flagVersionShort = "-v"
	flagHelp         = "--help"
	flagHelpShort    = "-h"

	modeBreach = "breach"
	modeMFA    = "mfa"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		osExit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("bva", flag.ContinueOnError)

	mode := fs.String(flagMode[2:], "", "Run mode (breach or mfa)")
	vaultFile := fs.String(flagFileShort[1:], "enpass.json", "Path to the Enpass JSON vault file")
	vaultFileLong := fs.String(flagFile[2:], "", "Path to the Enpass JSON vault file")
	checkAll := fs.Bool(flagAllShort[1:], false, "Check ALL passwords in the vault via k-Anonymity (ignores domain breach status)")
	checkAllLong := fs.Bool(flagAll[2:], false, "Check ALL passwords in the vault via k-Anonymity (ignores domain breach status)")
	var workers int
	fs.IntVar(&workers, flagWorkersShort[1:], 5, "Number of concurrent workers")
	fs.IntVar(&workers, flagWorkers[2:], 5, "Number of concurrent workers")
	outputDir := fs.String(flagOutputShort[1:], "", "Path to save the audit reports")
	outputDirLong := fs.String(flagOutput[2:], "", "Path to save the audit reports")
	force := fs.Bool(flagForce[2:], false, "Force update of local cache (mfa mode only)")
	versionFlag := fs.Bool(flagVersion[2:], false, "Print version and exit")

	if len(args) == 1 && (args[0] == flagVersion || args[0] == flagVersionShort) {
		fmt.Printf("Blind Breach Audit (BVA) %s\n", Version)
		return nil
	}

	setupHelp(mode, fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if *versionFlag {
		fmt.Printf("Blind Breach Audit (BVA) %s\n", Version)
		return nil
	}

	if err := parseMode(mode, fs.Args()); err != nil {
		fs.Usage()
		return err
	}

	finalCheckAll := *checkAll || *checkAllLong
	if err := validateFlags(*mode, finalCheckAll); err != nil {
		return err
	}

	finalVaultFile := *vaultFile
	if *vaultFileLong != "" {
		finalVaultFile = *vaultFileLong
	}

	finalOutputDir := *outputDir
	if *outputDirLong != "" {
		finalOutputDir = *outputDirLong
	}

	ctx := context.Background()
	httpClient := &http.Client{}
	userAgent := "Blind-Breach-Audit/" + Version
	hibpClient := hibp.NewClient(httpClient, userAgent)
	enpassProvider := parser.NewEnpassProvider()

	cfg := engine.Config{
		Mode:      *mode,
		CheckAll:  finalCheckAll,
		Workers:   workers,
		OutputDir: finalOutputDir,
		Force:     *force,
	}

	printBanner(Version)

	eng := engine.New(hibpClient, enpassProvider, cfg)
	if err := eng.Run(ctx, finalVaultFile); err != nil {
		return fmt.Errorf("engine run failed: %w", err)
	}
	return nil
}

func parseMode(mode *string, args []string) error {
	if *mode == "" && len(args) > 0 {
		if args[0] == modeBreach || args[0] == modeMFA {
			*mode = args[0]
		}
	}
	if *mode == "" {
		return fmt.Errorf("%s is required (%s or %s)", flagMode, modeBreach, modeMFA)
	}
	return nil
}

func validateFlags(mode string, finalCheckAll bool) error {
	if mode == modeMFA && finalCheckAll {
		return fmt.Errorf("%s or %s flag is only valid for mode: %s", flagAll, flagAllShort, modeBreach)
	}
	if mode != modeBreach && mode != modeMFA {
		return fmt.Errorf("invalid mode '%s'", mode)
	}
	return nil
}
