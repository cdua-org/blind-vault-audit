package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/cli/spinner"
	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
)

func (e *Engine) runMFA(ctx context.Context, items []parser.VaultItem) error {
	cacheMgr, err := cache.NewManager(e.config.HTTPClient, e.config.CacheOptions...)
	if err != nil {
		return fmt.Errorf("failed to init cache manager: %w", err)
	}

	data2FA, path2FA, mod2FA, err := e.fetchMFAData(ctx, cacheMgr, "2FA", "2fa_v1.json", cacheMgr.Fetch2FA)
	if err != nil {
		return fmt.Errorf("failed to fetch 2FA data: %w", err)
	}

	passkeysData, passkeysPath, passkeysMod, err := e.fetchMFAData(ctx, cacheMgr, "Passkeys", "passkeys_v1.json", cacheMgr.FetchPK)
	if err != nil {
		return fmt.Errorf("failed to fetch passkeys data: %w", err)
	}

	domains2FA, err := e.parse2FAData(data2FA)
	if err != nil {
		return err
	}

	passkeysDomains, err := e.parsePasskeysData(passkeysData)
	if err != nil {
		return err
	}

	var processed atomic.Int32
	stopSpinner := spinner.Start(ctx, "Auditing vault items...", &processed, len(items))

	list2FA, passkeyList := e.evaluateAllItems(items, domains2FA, passkeysDomains, &processed)

	stopSpinner()

	sort.Strings(list2FA)
	sort.Strings(passkeyList)

	var finalReport strings.Builder
	if len(list2FA) > 0 {
		msg := "\n[*] 2FA available but not configured:\n"
		fmt.Print(msg)
		finalReport.WriteString(msg)
		for _, s := range list2FA {
			fmt.Println(s)
			finalReport.WriteString(s + "\n")
		}
	}

	if len(passkeyList) > 0 {
		msg := "\n[*] Passkeys supported but not configured:\n"
		fmt.Print(msg)
		finalReport.WriteString(msg)
		for _, s := range passkeyList {
			fmt.Println(s)
			finalReport.WriteString(s + "\n")
		}
	}

	summary := fmt.Sprintf("\nAudit complete. Total 2FA recommendations: %d | Passkey Infos: %d\n", len(list2FA), len(passkeyList))
	fmt.Print(summary)
	finalReport.WriteString(summary)

	if path2FA != "" && passkeysPath != "" {
		cacheInfo := fmt.Sprintf("\nCache Information:\n  - 2FA:      %s (updated: %s)\n  - Passkeys: %s (updated: %s)\n\n",
			path2FA, mod2FA.Format("2006-01-02 15:04:05"),
			passkeysPath, passkeysMod.Format("2006-01-02 15:04:05"))
		fmt.Print(cacheInfo)
		finalReport.WriteString(cacheInfo)
	}

	if e.config.OutputDir != "" {
		outPath := filepath.Join(e.config.OutputDir, "mfa.txt")
		if err := os.MkdirAll(e.config.OutputDir, 0o750); err != nil {
			fmt.Printf("Failed to create output directory: %v\n", err)
		} else if err := os.WriteFile(outPath, []byte(finalReport.String()), 0o600); err != nil {
			fmt.Printf("Failed to save report to file: %v\n", err)
		} else {
			fmt.Printf("Report successfully saved to: %s\n", outPath)
		}
	}

	return nil
}

func (e *Engine) fetchMFAData(ctx context.Context, cacheMgr *cache.Manager, title, filename string, fetchFunc func(context.Context, bool) ([]byte, string, time.Time, bool, error)) (data []byte, path string, mod time.Time, err error) {
	label := fmt.Sprintf("Fetching %s database (downloaded)...", title)
	if !e.config.Force && cacheMgr.IsCached(filename) {
		label = fmt.Sprintf("Fetching %s database (cached)...", title)
	}
	stop := spinner.Start(ctx, label, nil, 0)
	data, path, mod, _, err = fetchFunc(ctx, e.config.Force)
	stop()
	return data, path, mod, err
}

func (e *Engine) parse2FAData(data []byte) (map[string]SecurityInfo, error) {
	var array2FA [][]any
	if err := json.Unmarshal(data, &array2FA); err != nil {
		return nil, fmt.Errorf("failed to parse 2FA json: %w", err)
	}

	domains2FA := make(map[string]SecurityInfo)
	for _, item := range array2FA {
		if len(item) <= 1 {
			continue
		}
		obj, ok := item[1].(map[string]any)
		if !ok {
			continue
		}
		domain, ok := obj["domain"].(string)
		if !ok {
			continue
		}
		methods2FA, ok := obj["tfa"].([]any)
		if !ok {
			continue
		}

		hasTOTP := false
		for _, method := range methods2FA {
			methodStr, ok := method.(string)
			if ok && methodStr == config.FieldTypeTOTP {
				hasTOTP = true
				break
			}
		}
		if hasTOTP {
			info := SecurityInfo{}
			if doc, ok := obj["documentation"].(string); ok {
				info.Documentation = doc
			}
			if notes, ok := obj["notes"].(string); ok {
				info.Notes = notes
			}
			domains2FA[strings.ToLower(domain)] = info
		}
	}
	return domains2FA, nil
}

func (e *Engine) parsePasskeysData(data []byte) (map[string]SecurityInfo, error) {
	var passkeysMap map[string]any
	if err := json.Unmarshal(data, &passkeysMap); err != nil {
		return nil, fmt.Errorf("failed to parse passkeys json: %w", err)
	}

	passkeysDomains := make(map[string]SecurityInfo)
	for domain, value := range passkeysMap {
		valMap, ok := value.(map[string]any)
		if !ok {
			continue
		}
		pless, ok := valMap["passwordless"].(string)
		if ok && pless == "allowed" {
			info := SecurityInfo{}
			if doc, ok := valMap["documentation"].(string); ok {
				info.Documentation = doc
			}
			if notes, ok := valMap["notes"].(string); ok {
				info.Notes = notes
			}
			passkeysDomains[strings.ToLower(domain)] = info
		}
	}
	return passkeysDomains, nil
}

func (e *Engine) evaluateMFAItem(item parser.VaultItem, domains2FA, passkeysDomains map[string]SecurityInfo) (local2FA, localPasskey []string) {
	var matched2FA, matchedPasskey []string
	var docs2FA, notes2FA, docsPasskey, notesPasskey []string

	for _, domain := range item.Domains {
		d := strings.ToLower(domain)

		if info, has2FA := domains2FA[d]; has2FA && !item.HasTOTP {
			matched2FA = append(matched2FA, d)
			if info.Documentation != "" && !slices.Contains(docs2FA, info.Documentation) {
				docs2FA = append(docs2FA, info.Documentation)
			}
			if info.Notes != "" && !slices.Contains(notes2FA, info.Notes) {
				notes2FA = append(notes2FA, info.Notes)
			}
		}

		if infoP, hasPasskey := passkeysDomains[d]; hasPasskey {
			matchedPasskey = append(matchedPasskey, d)
			if infoP.Documentation != "" && !slices.Contains(docsPasskey, infoP.Documentation) {
				docsPasskey = append(docsPasskey, infoP.Documentation)
			}
			if infoP.Notes != "" && !slices.Contains(notesPasskey, infoP.Notes) {
				notesPasskey = append(notesPasskey, infoP.Notes)
			}
		}
	}

	if len(matched2FA) > 0 {
		local2FA = append(local2FA, buildMFAMessage(item.Title, matched2FA, docs2FA, notes2FA))
	}

	if len(matchedPasskey) > 0 {
		localPasskey = append(localPasskey, buildMFAMessage(item.Title, matchedPasskey, docsPasskey, notesPasskey))
	}

	return local2FA, localPasskey
}

func buildMFAMessage(title string, matched, docs, notes []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, " - %s (Domain: %s)", title, strings.Join(matched, ", "))
	for _, doc := range docs {
		sb.WriteString("\n   Docs: " + doc)
	}
	for _, note := range notes {
		sb.WriteString("\n   Note: " + note)
	}
	return sb.String()
}

func (e *Engine) evaluateAllItems(items []parser.VaultItem, domains2FA, passkeysDomains map[string]SecurityInfo, processed *atomic.Int32) (list2FA, passkeyList []string) {
	var mu sync.Mutex

	for _, item := range items {
		local2FA, localPasskey := e.evaluateMFAItem(item, domains2FA, passkeysDomains)
		mu.Lock()
		list2FA = append(list2FA, local2FA...)
		passkeyList = append(passkeyList, localPasskey...)
		mu.Unlock()
		processed.Add(1)
	}
	return list2FA, passkeyList
}
