// Package main provides the entry point for the Blind Vault Audit CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/engine"
	"github.com/cdua-org/blind-vault-audit/internal/hibp"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
	"github.com/cdua-org/blind-vault-audit/internal/updater"
)

var (
	Version       = "dev"
	osExit        = os.Exit
	newHTTPClient = defaultHTTPClient
)

func defaultHTTPClient() *http.Client {
	return &http.Client{}
}

const (
	flagMode          = "--mode"
	flagFile          = "--file"
	flagFileShort     = "-f"
	flagPasswordsOnly = "--passwords-only"
	flagWorkers       = "--workers"
	flagWorkersShort  = "-w"
	flagOutput        = "--output"
	flagOutputShort   = "-o"
	flagForce         = "--force"
	flagVersion       = "--version"
	flagHelp          = "--help"
	flagHelpShort     = "-h"
)

const (
	colorError = "\033[1;31m"
	colorReset = "\033[0m"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			osExit(0)
			return
		}
		fmt.Fprintf(os.Stderr, "%sError: %v%s\n", colorError, err, colorReset)
		osExit(1)
	}
}

func run(args []string) error {
	updater.CleanupWindowsOldFiles()

	fs := flag.NewFlagSet("bva", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	mode := fs.String(flagMode[2:], "", "Run mode (breach or mfa)")
	vaultFile := fs.String(flagFileShort[1:], "", "Path to the JSON vault file")
	vaultFileLong := fs.String(flagFile[2:], "", "Path to the JSON vault file")
	checkPasswordsOnly := fs.Bool(flagPasswordsOnly[2:], false, "Check passwords exclusively via k-Anonymity (ignores domain breach status)")
	var workers int
	fs.IntVar(&workers, flagWorkersShort[1:], 5, "Number of concurrent workers")
	fs.IntVar(&workers, flagWorkers[2:], 5, "Number of concurrent workers")
	outputDir := fs.String(flagOutputShort[1:], "", "Path to save the audit reports")
	outputDirLong := fs.String(flagOutput[2:], "", "Path to save the audit reports")
	force := fs.Bool(flagForce[2:], false, "Force update of local cache (mfa mode only)")
	versionFlag := fs.Bool(flagVersion[2:], false, "Print version and exit")

	maybePrintBanner(mode, args)

	if len(args) == 1 && args[0] == flagVersion {
		return nil
	}

	if len(args) > 0 && args[0] == config.ModeUpdate {
		return handleUpdateCommand(args[1:])
	}

	if containsModeUpdate(args) {
		fmt.Fprintf(os.Stderr, "%sError: invalid mode '%s'%s\n\n", colorError, config.ModeUpdate, colorReset)
		printUsageExamples(config.ModeUpdate)
		return flag.ErrHelp
	}

	setupHelp(mode, args, fs)
	customUsage := fs.Usage
	fs.Usage = func() {}

	if len(args) == 0 || checkHelpFlagPresent(args) {
		customUsage()
		return flag.ErrHelp
	}

	if err := fs.Parse(args); err != nil {
		handleParseError(err, mode, args, customUsage)
		return flag.ErrHelp
	}

	if *versionFlag {
		return nil
	}

	if err := validateModeAndFlags(mode, args, fs.Args(), *checkPasswordsOnly); err != nil {
		return err
	}

	finalVaultFile := *vaultFile
	if *vaultFileLong != "" {
		finalVaultFile = *vaultFileLong
	}
	if finalVaultFile == "" {
		fmt.Fprintf(os.Stderr, "%sError: vault file path is required%s\n\n", colorError, colorReset)
		printUsageExamples(*mode)
		return flag.ErrHelp
	}

	finalOutputDir := *outputDir
	if *outputDirLong != "" {
		finalOutputDir = *outputDirLong
	}

	ctx := context.Background()
	httpClient := newHTTPClient()
	userAgent := "Blind-Breach-Audit/" + Version
	hibpClient := hibp.NewClient(httpClient, userAgent)
	enpassProvider := parser.NewEnpassProvider()

	cfg := engine.Config{
		Mode:       *mode,
		CheckAll:   *checkPasswordsOnly,
		Workers:    workers,
		OutputDir:  finalOutputDir,
		Force:      *force,
		HTTPClient: httpClient,
		CacheOptions: []cache.Option{
			cache.WithCacheDirFunc(osUserCacheDir),
		},
	}

	eng := engine.New(hibpClient, enpassProvider, &cfg)
	if err := eng.Run(ctx, finalVaultFile); err != nil {
		return fmt.Errorf("engine run failed: %w", err)
	}
	return nil
}

func handleParseError(err error, mode *string, args []string, showFullHelp func()) {
	errMsg := formatParseError(err)
	detectedMode := getModeForUsage(mode, args)
	if *mode == "" && detectedMode == config.ModeBreach {
		errMsg = strings.Replace(errMsg, "requires an argument",
			"requires "+flagMode+" "+config.ModeBreach+" and an argument", 1)
	}
	fmt.Fprintf(os.Stderr, "%sError: %s%s\n\n", colorError, errMsg, colorReset)
	if strings.HasPrefix(errMsg, "unknown flag ") {
		showFullHelp()
	} else {
		printUsageExamples(detectedMode)
	}
}

func formatParseError(err error) string {
	errMsg := err.Error()
	if strings.HasPrefix(errMsg, "flag provided but not defined:") {
		flagName := strings.TrimSpace(strings.Split(errMsg, "flag provided but not defined:")[1])
		return "unknown flag " + flagName
	}
	if strings.Contains(errMsg, "flag needs an argument") {
		if strings.Contains(errMsg, flagFileShort) || strings.Contains(errMsg, flagFile) {
			return fmt.Sprintf("flag %s or %s requires an argument", flagFile, flagFileShort)
		}
		if strings.Contains(errMsg, flagOutputShort) || strings.Contains(errMsg, flagOutput) {
			return fmt.Sprintf("flag %s or %s requires an argument", flagOutput, flagOutputShort)
		}
		if strings.Contains(errMsg, flagWorkersShort) || strings.Contains(errMsg, flagWorkers) {
			return fmt.Sprintf("flag %s or %s requires an argument", flagWorkers, flagWorkersShort)
		}
		if strings.Contains(errMsg, "-mode") {
			return fmt.Sprintf("flag %s requires an argument (breach or mfa)", flagMode)
		}
	}
	return errMsg
}

func checkHelpFlagPresent(args []string) bool {
	for _, arg := range args {
		if arg == flagHelpShort || arg == flagHelp {
			return true
		}
	}
	return false
}

func containsModeUpdate(args []string) bool {
	for i, arg := range args {
		if (arg == flagMode || arg == "-mode") && i+1 < len(args) && args[i+1] == config.ModeUpdate {
			return true
		}
	}
	return false
}

func maybePrintBanner(_ *string, args []string) {
	if len(args) == 1 && args[0] == config.ModeUpdate {
		return
	}
	printBanner(Version)
}

func validateModeAndFlags(mode *string, rawArgs, remaining []string, checkPasswordsOnly bool) error {
	if err := parseMode(mode, remaining); err != nil {
		detectedMode := getModeForUsage(mode, rawArgs)
		if detectedMode == config.ModeBreach {
			fmt.Fprintf(os.Stderr, "%sError: %s%s\n\n", colorError, requiresBreachMode(rawArgs), colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "%sError: %v%s\n\n", colorError, err, colorReset)
		}
		printUsageExamples(detectedMode)
		return flag.ErrHelp
	}

	if err := validateFlags(*mode, checkPasswordsOnly); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %v%s\n\n", colorError, err, colorReset)
		printUsageExamples(*mode)
		return flag.ErrHelp
	}

	return nil
}

func handleUpdateCommand(args []string) error {
	if checkHelpFlagPresent(args) {
		fs := flag.NewFlagSet("update", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		updateMode := config.ModeUpdate
		setupHelp(&updateMode, args, fs)
		fs.Usage()
		return flag.ErrHelp
	}

	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "%sError: unknown flag '%s' for update command%s\n\n", colorError, args[0], colorReset)
		printUsageExamples(config.ModeUpdate)
		return flag.ErrHelp
	}

	return runUpdate()
}

func runUpdate() error {
	ctx := context.Background()
	httpClient := newHTTPClient()
	err := updater.Update(ctx, httpClient, Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sUpdate failed: %v%s\n", colorError, err, colorReset)
	}
	return nil
}

func getModeForUsage(mode *string, args []string) string {
	if mode != nil && *mode != "" {
		return *mode
	}
	for _, arg := range args {
		if arg == config.ModeBreach || arg == config.ModeMFA || arg == config.ModeUpdate {
			return arg
		}
		if arg == flagPasswordsOnly || arg == flagWorkers || arg == flagWorkersShort {
			return config.ModeBreach
		}
	}
	return ""
}

func requiresBreachMode(args []string) string {
	for _, arg := range args {
		if arg == flagPasswordsOnly || arg == flagWorkers || arg == flagWorkersShort {
			return arg + " requires " + flagMode + " " + config.ModeBreach
		}
	}
	return flagMode + " is required (" + config.ModeBreach + " or " + config.ModeMFA + ")"
}

func parseMode(mode *string, args []string) error {
	if *mode == config.ModeUpdate {
		return fmt.Errorf("invalid mode '%s'", *mode)
	}
	if *mode == "" && len(args) > 0 {
		if args[0] == config.ModeBreach || args[0] == config.ModeMFA || args[0] == config.ModeUpdate {
			*mode = args[0]
		}
	}
	if *mode == "" {
		return fmt.Errorf("%s is required (%s or %s)", flagMode, config.ModeBreach, config.ModeMFA)
	}
	return nil
}

func validateFlags(mode string, passwordsOnly bool) error {
	if mode != config.ModeBreach && passwordsOnly {
		return fmt.Errorf("%s flag is only valid for mode: %s", flagPasswordsOnly, config.ModeBreach)
	}
	if mode != config.ModeBreach && mode != config.ModeMFA && mode != config.ModeUpdate {
		return fmt.Errorf("invalid mode '%s'", mode)
	}
	return nil
}
