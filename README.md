# Blind Vault Audit (bva)

`bva` is a command-line utility for security auditing of password manager vaults with a strict focus on data privacy. It evaluates credential exposure and Multi-Factor Authentication (MFA) / Passkey readiness by performing local analysis against datasets fetched via public APIs. Sensitive vault data is never transmitted to third-party services.

## Motivation

Password managers are essential for digital security. However, a growing trend in the industry is to lock critical security auditing features behind recurring subscription paywalls — even for users who have purchased perpetual licenses or rely on free tiers.

For example, without a premium subscription, some password managers will check your passwords for free, but actively hide other critical alerts behind a paywall. They might warn you that "X of your saved websites suffered data breaches", "Y of your accounts support 2FA", or "Z of your accounts support Passkeys", while refusing to reveal **which specific websites** those are.

**Blind Vault Audit (bva)** was created to address this gap.

## Architecture & Security Model

The tool is designed with strict data privacy constraints:

- **k-Anonymity Password Auditing**: Passwords are never transmitted. The tool computes a SHA-1 hash of each password locally and transmits the prefix (only the first 5 characters of the hash) to the Have I Been Pwned (HIBP) API. The API returns all hash suffixes matching the prefix, and the full comparison is performed locally in memory.
- **Offline 2FA & Passkey Evaluation**: To determine 2FA and Passkey support, `bva` makes network requests solely to fetch and cache the full datasets from 2fa.directory and passkeys.2fa.directory. Once cached, the vault is parsed and evaluated entirely offline. Vault domain structures are never transmitted.
- **No Built-in Telemetry**: The `bva` tool itself collects zero telemetry and tracks no usage data.
- **Restricted Outbound Connections**: Outbound network requests are strictly limited to fetching public security datasets from third-party APIs ([HIBP](https://haveibeenpwned.com), [2fa.directory](https://2fa.directory), [passkeys.2fa.directory](https://passkeys.2fa.directory)).

Currently supported vault formats:
- [Enpass](https://www.enpass.io) (JSON export)

## Installation

You can download the pre-compiled binary for your architecture (Linux, macOS, Windows) directly from the [Releases](https://github.com/cdua-org/blind-vault-audit/releases) page. The binaries are packed as `.tar.gz` (for Linux/macOS) or `.zip` (for Windows).

1. Download the archive for your system.
2. Unpack the downloaded archive into the directory where you want to keep the utility.
3. Open a terminal (or command prompt) and run the utility from that folder.
*(For Unix-like systems, you can optionally move the binary to a directory in your PATH, such as `/usr/local/bin`)*

<details>
<summary><b>Example: Manual Installation (macOS Apple Silicon)</b></summary>

Below is an example of how to manually download, extract, and install the macOS Apple Silicon (ARM64) binary. You can modify the variables for your specific OS/Architecture:

```bash
# 1. Set the variables for your target system
REPO="cdua-org/blind-vault-audit"
VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | head -n 1 | awk -F'"' '{print $4}')
ASSET_NAME="bva-darwin-arm64.tar.gz"
INSTALL_DIR="/usr/local/bin"

# 2. Download the archive
curl -sSL -O "https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

# 3. Extract only the binary from the archive
tar -xzf "${ASSET_NAME}" bva

# 4. Install the binary (requires sudo if moving to /usr/local/bin)
sudo mv bva "${INSTALL_DIR}/"

# 5. Clean up
rm "${ASSET_NAME}"
```

</details>

Once installed, refer to the CLI Reference section below to get started.

## CLI Reference

The default cache location for fetched datasets depends on the operating system:
- **macOS**: `~/Library/Caches/bva`
- **Linux**: `~/.cache/bva`
- **Windows**: `%LocalAppData%\bva`

```text
Usage:
  bva --mode <breach|mfa> [options]
  bva --version

Modes:
  breach   Check passwords against Have I Been Pwned database
  mfa      Check security posture (2FA and Passkey support)

Tip: Run 'bva --mode <mode> --help' for mode-specific options.

Global Options:
  -h, --help            Print this help message and exit
```

<details>
<summary><b>Mode: Breach Detection</b></summary>

The `breach` mode audits your passwords against the HIBP database:
- **Domain Cross-Referencing**: Fetches the HIBP breach database to extract compromised domains along with their breach dates and leaked data classes. To prevent false positives, breaches that did not expose passwords are automatically skipped. The remaining domains are cross-referenced locally against the vault. If a match is found, it is reported, and the breach date from the dataset is compared locally against the password's update timestamp:
  - If the breach occurred after the password was last updated, a critical alert is generated.
  - If the password was changed after the breach, an alert is generated if the new password is found in the Pwned Passwords database, otherwise a "safe" notification is generated confirming successful mitigation.
- **Password Auditing**: Passwords are evaluated via the HIBP k-Anonymity API.
- **Password-Only Mode**: Using the `--passwords-only` flag acts as an independent audit: it evaluates *every password* in the vault exclusively against the Pwned Passwords database. Domain breach data is completely ignored and not reported in this mode.
- Maintains a local cache directory for HIBP breach data with a **24-hour TTL** (use the `--force` flag to bypass the cache and force an update). When operating from a valid cache, the only network requests executed are the k-Anonymity password checks.
- Supports concurrent execution for API requests via the `--workers` flag.

```text
Usage:
  bva --mode breach --file <VAULT PATH> [--passwords-only] [--force] [--output <REPORT DIR PATH>] [--workers <NUM>]
  bva --mode breach --help

Options:
  -f, --file            Path to the JSON vault file
  -o, --output          Path to save the audit reports directory
      --passwords-only  Check all passwords, ignoring domain breach dates.
      --force           Force update of local breach cache database, ignoring TTL
  -w, --workers         Number of concurrent workers for HIBP checks (default: 5).
                        Higher numbers check faster but use more resources.
  -h, --help            Print this help message and exit
```

</details>

<details>
<summary><b>Mode: 2FA & Passkey Evaluation</b></summary>

The `mfa` mode evaluates your accounts for missing security configurations:
- Parses vault entries to identify accounts lacking configured TOTP, despite service support.
- Provides an informational summary of vault services (domains) that currently support Passkeys.
- Maintains a local cache directory for MFA datasets with a **24-hour TTL** (use the `--force` flag to bypass the cache and force an update).

```text
Usage:
  bva --mode mfa --file <VAULT PATH> [--force] [--output <REPORT DIR PATH>]
  bva --mode mfa --help

Options:
  -f, --file            Path to the JSON vault file
  -o, --output          Path to save the audit reports directory
      --force           Force update of local MFA cache databases, ignoring TTL
  -h, --help            Print this help message and exit
```

</details>
