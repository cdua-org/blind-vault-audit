package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/cache"
	"github.com/cdua-org/blind-vault-audit/internal/cli/spinner"
	"github.com/cdua-org/blind-vault-audit/internal/parser"
)

func (e *Engine) runBreach(ctx context.Context, items []parser.VaultItem) error {
	cacheMgr, err := cache.NewManager(&http.Client{}, e.config.CacheOptions...)
	if err != nil {
		return fmt.Errorf("failed to init cache manager: %w", err)
	}

	breachesData, breachesPath, breachesMod, errFetch := e.fetchBreachesData(ctx, cacheMgr)
	if errFetch != nil {
		return fmt.Errorf("failed to fetch breaches: %w", errFetch)
	}

	breaches, err := e.parseBreachData(breachesData)
	if err != nil {
		return err
	}

	var processed atomic.Int32
	stopSpinner := spinner.Start(ctx, "Auditing vault items...", &processed, len(items))

	var compromisedTitles []string
	var allReports []string
	var mu sync.Mutex

	itemCh := make(chan parser.VaultItem, len(items))
	for _, item := range items {
		itemCh <- item
	}
	close(itemCh)

	numWorkers := e.config.Workers
	if numWorkers <= 0 {
		numWorkers = 5
	}
	if numWorkers > len(items) && len(items) > 0 {
		numWorkers = len(items)
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for range numWorkers {
		go func() {
			defer wg.Done()
			for item := range itemCh {
				isComp, report := e.processItem(ctx, item, breaches)

				mu.Lock()
				if report != "" {
					allReports = append(allReports, report)
				}
				if isComp {
					compromisedTitles = append(compromisedTitles, item.Title)
				}
				mu.Unlock()

				processed.Add(1)
			}
		}()
	}

	wg.Wait()
	stopSpinner()

	sort.Strings(compromisedTitles)

	e.printAndSaveBreachReport(allReports, compromisedTitles, breachesPath, breachesMod)

	return nil
}

func (e *Engine) printAndSaveBreachReport(allReports, compromisedTitles []string, breachesPath string, breachesMod time.Time) {
	var finalReport strings.Builder

	if len(allReports) > 0 {
		fmt.Println()
		finalReport.WriteString("\n")
		for _, report := range allReports {
			fmt.Print(report)
			finalReport.WriteString(report)
		}
	}

	summary := fmt.Sprintf("Audit complete. Total compromised/vulnerable items found: %d\n", len(compromisedTitles))
	fmt.Print(summary)
	finalReport.WriteString(summary)

	if len(compromisedTitles) > 0 {
		hdr := "\nCompromised entries:\n"
		fmt.Print(hdr)
		finalReport.WriteString(hdr)
		for _, title := range compromisedTitles {
			tStr := fmt.Sprintf(" - %s\n", title)
			fmt.Print(tStr)
			finalReport.WriteString(tStr)
		}
		fmt.Println()
		finalReport.WriteString("\n")
	}

	if !e.config.CheckAll && breachesPath != "" {
		cacheInfo := fmt.Sprintf("\nCache Information:\n  - Breaches: %s (updated: %s)\n",
			breachesPath, breachesMod.Format("2006-01-02 15:04:05"))
		fmt.Print(cacheInfo)
		finalReport.WriteString(cacheInfo)
	}

	if e.config.OutputDir != "" {
		e.saveReportToFile(finalReport.String(), "breaches.txt")
	}
}

func (e *Engine) saveReportToFile(reportContent, filename string) {
	outPath := filepath.Join(e.config.OutputDir, filename)
	cleanReport := strings.ReplaceAll(reportContent, "\033[31;1m", "")
	cleanReport = strings.ReplaceAll(cleanReport, "\033[0m", "")
	if err := os.MkdirAll(e.config.OutputDir, 0o750); err != nil {
		fmt.Printf("Failed to create output directory: %v\n", err)
	} else if err := os.WriteFile(outPath, []byte(cleanReport), 0o600); err != nil {
		fmt.Printf("Failed to save report to file: %v\n", err)
	} else {
		fmt.Printf("Report successfully saved to: %s\n", outPath)
	}
}

func (e *Engine) fetchBreachesData(ctx context.Context, cacheMgr *cache.Manager) (breachesData []byte, breachesPath string, breachesMod time.Time, err error) {
	label := "Fetching latest breach database (downloaded)..."
	if !e.config.Force && cacheMgr.IsCached("breaches_v1.json") {
		label = "Fetching latest breach database (cached)..."
	}

	stopFetch := spinner.Start(ctx, label, nil, 0)
	breachesData, breachesPath, breachesMod, _, errFetch := cacheMgr.FetchBreaches(ctx, e.config.Force)
	stopFetch()
	if errFetch != nil {
		errFetch = fmt.Errorf("failed to fetch breaches data: %w", errFetch)
	}
	return breachesData, breachesPath, breachesMod, errFetch
}

func (e *Engine) parseBreachData(breachesData []byte) (map[string]BreachInfo, error) {
	var parsed []map[string]any
	if err := json.Unmarshal(breachesData, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse breaches json: %w", err)
	}

	breaches := make(map[string]BreachInfo)
	for _, b := range parsed {
		name, okName := b["Name"].(string)
		title, okTitle := b["Title"].(string)
		domain, okDomain := b["Domain"].(string)
		breachDateStr, okDate := b["BreachDate"].(string)
		dataClassesInterface, okData := b["DataClasses"].([]any)

		if !okName || !okDate || !okTitle {
			continue
		}

		breachTs := int64(0)
		t, err := time.Parse("2006-01-02", breachDateStr)
		if err == nil {
			breachTs = t.Unix()
		}

		var classes []string
		if okData {
			for _, class := range dataClassesInterface {
				if cStr, okC := class.(string); okC {
					classes = append(classes, cStr)
				}
			}
		}

		info := BreachInfo{
			Title:       title,
			BreachDate:  breachTs,
			DataClasses: classes,
		}

		breaches[strings.ToLower(name)] = info
		if okDomain && domain != "" {
			breaches[strings.ToLower(domain)] = info
		}
	}
	return breaches, nil
}

func (e *Engine) processItem(ctx context.Context, item parser.VaultItem, breaches map[string]BreachInfo) (isCompromised bool, report string) {
	var breachTs int64
	var breachedDomains []string
	var leakedData []string
	isCompromised = e.config.CheckAll

	if !e.config.CheckAll {
		isCompromised, breachTs, breachedDomains, leakedData = e.checkBreachedDomains(item, breaches)
	}

	if !isCompromised {
		return false, ""
	}

	var sb strings.Builder
	if !e.config.CheckAll {
		for i, domain := range breachedDomains {
			fmt.Fprintf(&sb, "[!] Vulnerable domain %s found in entry: %s\n", domain, item.Title)
			if leakedData[i] != "" {
				fmt.Fprintf(&sb, "    Leaked: %s\n", leakedData[i])
			}
		}
	} else {
		fmt.Fprintf(&sb, "[*] Checking entry: %s\n", item.Title)
	}

	if len(item.Passwords) == 0 {
		sb.WriteString("    [i] No password found for this entry (possible false positive or biometrics used).\n\n")
		return false, sb.String()
	}

	isSafe, pwReport := e.checkPasswordsConcurrently(ctx, item, breachTs)
	sb.WriteString(pwReport)

	return !isSafe, sb.String()
}

func (e *Engine) checkPasswordsConcurrently(ctx context.Context, item parser.VaultItem, breachTs int64) (isSafe bool, report string) {
	isSafe = true
	var compromisedMessages []string
	var wg sync.WaitGroup
	msgCh := make(chan string, len(item.Passwords))
	safeCh := make(chan bool, len(item.Passwords))

	for _, pw := range item.Passwords {
		wg.Add(1)
		go e.checkSinglePassword(ctx, pw, breachTs, &wg, safeCh, msgCh)
	}

	go func() {
		wg.Wait()
		close(msgCh)
		close(safeCh)
	}()

	for safe := range safeCh {
		if !safe {
			isSafe = false
		}
	}

	for msg := range msgCh {
		compromisedMessages = append(compromisedMessages, msg)
	}

	report = e.formatResult(item, isSafe, breachTs, compromisedMessages)
	return isSafe, report
}

func (e *Engine) checkSinglePassword(ctx context.Context, password parser.PasswordEntry, breachTs int64, wg *sync.WaitGroup, safeCh chan<- bool, msgCh chan<- string) {
	defer wg.Done()

	pwnCount, err := e.hibpClient.CheckPasswordPwned(ctx, password.Value)
	if err != nil {
		pwnCount = 0
	}

	pwDateStr := "Unknown"
	if password.UpdatedAt > 0 {
		pwDateStr = time.Unix(password.UpdatedAt, 0).UTC().Format("2006-01-02")
	}

	switch {
	case pwnCount > 0:
		safeCh <- false
		msgCh <- fmt.Sprintf("        [X] Password (updated %s) found in HIBP leaks (Pwned %d times)!", pwDateStr, pwnCount)
	case !e.config.CheckAll && password.UpdatedAt <= breachTs:
		safeCh <- false
		msgCh <- fmt.Sprintf("        [!] Password (updated %s) is older than the breach (but NOT found in global leaks)!", pwDateStr)
	default:
		safeCh <- true
	}
}

func (e *Engine) formatResult(item parser.VaultItem, isSafe bool, breachTs int64, compromisedMessages []string) string {
	var sb strings.Builder
	breachDateStr := time.Unix(breachTs, 0).UTC().Format("2006-01-02")

	if isSafe {
		if !e.config.CheckAll {
			maxPwTs := int64(0)
			for _, p := range item.Passwords {
				if p.UpdatedAt > maxPwTs {
					maxPwTs = p.UpdatedAt
				}
			}
			pwDateStr := time.Unix(maxPwTs, 0).UTC().Format("2006-01-02")
			sb.WriteString("    [+] Password updated AFTER the breach and NOT found in global leaks (safe).\n")
			fmt.Fprintf(&sb, "        Breach Date:   %s\n", breachDateStr)
			fmt.Fprintf(&sb, "        Password Date: %s\n\n", pwDateStr)
		} else {
			sb.WriteString("    [+] Password is NOT found in global leaks (safe).\n\n")
		}
		return sb.String()
	}

	sb.WriteString("    \033[31;1m[!] IMMEDIATE ACTION REQUIRED.\033[0m\n")
	if !e.config.CheckAll {
		fmt.Fprintf(&sb, "        Breach Date:   %s\n", breachDateStr)
	}
	for _, msg := range compromisedMessages {
		sb.WriteString(msg + "\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

func (e *Engine) checkBreachedDomains(item parser.VaultItem, breaches map[string]BreachInfo) (isCompromised bool, breachTs int64, breachedDomains, leakedData []string) {
	for _, domain := range item.Domains {
		bInfo, ok := breaches[domain]
		if !ok {
			continue
		}

		hasPasswords := false
		for _, class := range bInfo.DataClasses {
			if class == DataClassPasswords || class == "Passwords (plaintext)" {
				hasPasswords = true
				break
			}
		}
		if !hasPasswords {
			continue
		}

		isCompromised = true
		if bInfo.BreachDate > breachTs {
			breachTs = bInfo.BreachDate
		}
		breachedDomains = append(breachedDomains, domain)
		if len(bInfo.DataClasses) > 0 {
			leakedData = append(leakedData, strings.Join(bInfo.DataClasses, ", "))
		} else {
			leakedData = append(leakedData, "")
		}
	}
	return
}
