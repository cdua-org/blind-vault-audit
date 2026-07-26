package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cdua-org/blind-vault-audit/internal/config"
)

const (
	bannerPad = "   "
)

func defaultUserCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user cache dir: %w", err)
	}
	return dir, nil
}

var osUserCacheDir = defaultUserCacheDir

func printBanner(version string) {
	gold := "\033[38;2;204;135;4m"
	darkGold := "\033[38;2;102;68;2m"
	darkGoldBg := "\033[48;2;102;68;2m"
	resetBg := "\033[49m"
	reset := "\033[0m"
	dim := "\033[38;2;221;178;177m"
	bold := "\033[1m"

	shade := "\u2591"
	full := "\u2588"
	top := "\u2580"
	bottom := "\u2584"
	space := " "

	halfShadow := darkGold + bottom + gold
	cornerShadow := darkGoldBg + top + resetBg

	topB := shade + full + top + top + bottom
	middleB := shade + full + top + top + cornerShadow + bottom
	bottomB := shade + full + bottom + bottom + bottom + top

	topA := halfShadow + bottom + top + bottom
	middleA := shade + full + bottom + bottom + bottom + full
	bottomA := shade + full + space + space + shade + full

	halfShadowFlipped := darkGold + top + gold
	topV := shade + full + space + space + shade + full
	middleV := shade + full + space + space + shade + full
	bottomV := space + halfShadowFlipped + top + bottom + top

	fmt.Fprint(os.Stderr, gold+"\n")
	fmt.Fprintf(os.Stderr, "%s%s  %s  %s\n", bannerPad, topB, topV, topA)
	fmt.Fprintf(os.Stderr, "%s%s %s %s\n", bannerPad, middleB, middleV, middleA)
	fmt.Fprintf(os.Stderr, "%s%s %s  %s\n", bannerPad, bottomB, bottomV, bottomA)
	fmt.Fprint(os.Stderr, reset+"\n")

	fmt.Fprintf(os.Stderr, "%s%s:: %sBlind Vault Audit (bva)%s %s%s ::%s\n", bannerPad, dim, bold, reset+dim, version, dim, reset)
	fmt.Fprintf(os.Stderr, "%s%s:: Detects breached credentials (k-Anonymity) ::%s\n", bannerPad, dim, reset)
	fmt.Fprintf(os.Stderr, "%s%s:: Offline 2FA & Passkey evaluation ::%s\n\n", bannerPad, dim, reset)
}

func setupHelp(mode *string, fs *flag.FlagSet) {
	fs.Usage = func() {
		printBanner(Version)

		cacheDir, err := osUserCacheDir()
		if err == nil && cacheDir != "" {
			cacheDir = filepath.Join(cacheDir, "bva")
		} else {
			cacheDir = "unknown (could not determine user cache dir)"
		}

		if mode == nil || *mode == "" {
			fmt.Fprintf(os.Stderr, "Usage:\n")
			fmt.Fprintf(os.Stderr, "  bva %s <%s|%s> [options]\n\n", flagMode, config.ModeBreach, config.ModeMFA)
			fmt.Fprintf(os.Stderr, "Modes:\n")
			fmt.Fprintf(os.Stderr, "  %s   Check passwords against Have I Been Pwned database\n", config.ModeBreach)
			fmt.Fprintf(os.Stderr, "  %s      Check security posture (2FA and Passkey support)\n\n", config.ModeMFA)
			fmt.Fprintf(os.Stderr, "Run 'bva %s <mode> %s' for mode-specific options.\n\n", flagMode, flagHelp)
			fmt.Fprintf(os.Stderr, "Global Options:\n")
			fmt.Fprintf(os.Stderr, "      %-18s  Print version and exit\n", flagVersion)
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Print this help message and exit\n\n", flagHelpShort, flagHelp)
			fmt.Fprintf(os.Stderr, "Cache Directory: %s\n\n", cacheDir)
			return
		}

		switch *mode {
		case config.ModeBreach:
			fmt.Fprintf(os.Stderr, "Mode: %s - Check passwords against HIBP database\n\n", config.ModeBreach)
			fmt.Fprintf(os.Stderr, "Usage:\n")
			fmt.Fprintf(os.Stderr, "  bva %s %s %s <VAULT PATH> [%s] [%s] [%s <REPORT DIR PATH>] [%s <NUM>]\n", flagMode, config.ModeBreach, flagFile, flagAll, flagForce, flagOutput, flagWorkers)
			fmt.Fprintf(os.Stderr, "  bva %s %s %s <VAULT PATH> [%s] [%s] [%s <REPORT DIR PATH>] [%s <NUM>]\n\n", flagMode, config.ModeBreach, flagFileShort, flagAllShort, flagForce, flagOutputShort, flagWorkersShort)
			fmt.Fprintf(os.Stderr, "Options:\n")
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Path to the Enpass JSON vault file (default \"enpass.json\")\n", flagFileShort, flagFile)
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Path to save the audit reports directory\n", flagOutputShort, flagOutput)
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Check all passwords, ignoring domain breach dates.\n", flagAllShort, flagAll)
			fmt.Fprintf(os.Stderr, "      %-18s  Force update of local breach cache database, ignoring TTL\n", flagForce)
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Number of concurrent workers for HIBP checks (default: 5).\n", flagWorkersShort, flagWorkers)
			fmt.Fprintf(os.Stderr, "                          Higher numbers check faster but use more resources.\n")
		case config.ModeMFA:
			fmt.Fprintf(os.Stderr, "Mode: %s - Check security posture (2FA and Passkey support)\n\n", config.ModeMFA)
			fmt.Fprintf(os.Stderr, "Usage:\n")
			fmt.Fprintf(os.Stderr, "  bva %s %s %s <VAULT PATH> [%s] [%s <REPORT DIR PATH>]\n", flagMode, config.ModeMFA, flagFile, flagForce, flagOutput)
			fmt.Fprintf(os.Stderr, "  bva %s %s %s <VAULT PATH> [%s] [%s <REPORT DIR PATH>]\n\n", flagMode, config.ModeMFA, flagFileShort, flagForce, flagOutputShort)
			fmt.Fprintf(os.Stderr, "Options:\n")
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Path to the Enpass JSON vault file (default \"enpass.json\")\n", flagFileShort, flagFile)
			fmt.Fprintf(os.Stderr, "  %s, %-14s  Path to save the audit reports directory\n", flagOutputShort, flagOutput)
			fmt.Fprintf(os.Stderr, "      %-18s  Force update of local MFA cache databases, ignoring TTL\n", flagForce)
		default:
			fmt.Fprintf(os.Stderr, "Unknown mode: %s\n\n", *mode)
			fmt.Fprintf(os.Stderr, "Available modes:\n  %s\n  %s\n", config.ModeBreach, config.ModeMFA)
			return
		}

		fmt.Fprintf(os.Stderr, "      %-18s  Print version and exit\n", flagVersion)
		fmt.Fprintf(os.Stderr, "  %s, %-14s  Print this help message and exit\n\n", flagHelpShort, flagHelp)
		fmt.Fprintf(os.Stderr, "Cache Directory: %s\n\n", cacheDir)
	}
}
