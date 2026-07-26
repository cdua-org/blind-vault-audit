package engine

import (
	"context"
	"encoding/json"
	"fmt"
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
	cacheMgr, err := cache.NewManager(e.config.HTTPClient, e.config.CacheOptions...)
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

	allReports := make([]string, 0, len(items))
	var compromisedEntries []compromisedEntry
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
				isComp, compNames, report := e.processItem(ctx, item, breaches)

				mu.Lock()
				if report != "" {
					allReports = append(allReports, report)
				}
				if isComp {
					compromisedEntries = append(compromisedEntries, compromisedEntry{
						Title: item.Title,
						Names: compNames,
					})
				}
				mu.Unlock()

				processed.Add(1)
			}
		}()
	}

	wg.Wait()
	stopSpinner()

	sort.Slice(compromisedEntries, func(i, j int) bool {
		return compromisedEntries[i].Title < compromisedEntries[j].Title
	})

	e.printAndSaveBreachReport(allReports, compromisedEntries, breachesPath, breachesMod)

	return nil
}

type compromisedEntry struct {
	Title string
	Names []string
}

func (e *Engine) printAndSaveBreachReport(allReports []string, compromisedEntries []compromisedEntry, breachesPath string, breachesMod time.Time) {
	var finalReport strings.Builder

	if len(allReports) > 0 {
		fmt.Println()
		finalReport.WriteString("\n")
		for _, report := range allReports {
			fmt.Print(report)
			finalReport.WriteString(report)
		}
	}

	summary := fmt.Sprintf("Audit complete. Total compromised/vulnerable items found: %d\n", len(compromisedEntries))
	fmt.Print(summary)
	finalReport.WriteString(summary)

	if len(compromisedEntries) > 0 {
		hdr := "\nCompromised entries:\n"
		fmt.Print(hdr)
		finalReport.WriteString(hdr)
		for _, entry := range compromisedEntries {
			tStr := fmt.Sprintf(" - %s [%s]\n", entry.Title, strings.Join(entry.Names, ", "))
			fmt.Print(tStr)
			finalReport.WriteString(tStr)
		}
		fmt.Println()
		finalReport.WriteString("\n")
	}

	if !e.config.CheckAll && breachesPath != "" {
		cacheInfo := fmt.Sprintf("\nCache Information:\n  - Breaches: %s (updated: %s)\n\n",
			breachesPath, breachesMod.Format("2006-01-02 15:04:05"))
		fmt.Print(cacheInfo)
		finalReport.WriteString(cacheInfo)
	} else {
		fmt.Println()
		finalReport.WriteString("\n")
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

func (e *Engine) processItem(ctx context.Context, item parser.VaultItem, breaches map[string]BreachInfo) (isCompromised bool, compNames []string, report string) {
	var breachTs int64
	var breachedDomains []string
	var leakedData []string
	isCompromised = e.config.CheckAll

	if !e.config.CheckAll {
		isCompromised, breachTs, breachedDomains, leakedData = e.checkBreachedDomains(item, breaches)
	}

	if !isCompromised {
		return false, nil, ""
	}

	var sb strings.Builder
	if !e.config.CheckAll {
		for i, domain := range breachedDomains {
			fmt.Fprintf(&sb, "[!] Vulnerable domain %s found in entry: %s\n", domain, item.Title)
			breachDateStr := time.Unix(breachTs, 0).UTC().Format("2006-01-02")
			fmt.Fprintf(&sb, "    Breach Date: %s\n", breachDateStr)
			if leakedData[i] != "" {
				fmt.Fprintf(&sb, "    Leaked: %s\n", leakedData[i])
			}
		}
	} else {
		fmt.Fprintf(&sb, "[*] Checking entry: %s\n", item.Title)
	}

	if len(item.Passwords) == 0 {
		sb.WriteString("    [i] No password found for this entry (possible false positive or biometrics used).\n\n")
		return false, nil, sb.String()
	}

	isSafe, compromisedNames, pwReport := e.checkPasswordsConcurrently(ctx, item, breachTs)
	sb.WriteString(pwReport)

	return !isSafe, compromisedNames, sb.String()
}

type pwCheckResult struct {
	Message string
	NameStr string
	Index   int
	IsSafe  bool
}

func (e *Engine) checkPasswordsConcurrently(ctx context.Context, item parser.VaultItem, breachTs int64) (isSafe bool, compromisedNames []string, report string) {
	var wg sync.WaitGroup
	resCh := make(chan pwCheckResult, len(item.Passwords))
	totalPws := len(item.Passwords)

	for i, pw := range item.Passwords {
		wg.Add(1)
		go e.checkSinglePassword(ctx, pw, i+1, totalPws, breachTs, &wg, resCh)
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var results []pwCheckResult
	for res := range resCh {
		results = append(results, res)
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Index < results[j].Index
	})

	isSafe = true
	for _, res := range results {
		if !res.IsSafe {
			isSafe = false
			compromisedNames = append(compromisedNames, res.NameStr)
		}
	}

	report = e.formatResult(results, isSafe)
	return isSafe, compromisedNames, report
}

func (e *Engine) checkSinglePassword(ctx context.Context, password parser.PasswordEntry, pwIndex, totalPws int, breachTs int64, wg *sync.WaitGroup, resCh chan<- pwCheckResult) {
	defer wg.Done()

	pwnCount, err := e.hibpClient.CheckPasswordPwned(ctx, password.Value)
	if err != nil {
		pwnCount = 0
	}

	pwDateStr := "Unknown"
	if password.UpdatedAt > 0 {
		pwDateStr = time.Unix(password.UpdatedAt, 0).UTC().Format("2006-01-02")
	}

	label := password.Label
	if label == "" {
		label = "Password"
	}

	nameStr := fmt.Sprintf("Password '%s'", label)
	if totalPws > 1 {
		nameStr = fmt.Sprintf("Password #%d '%s'", pwIndex, label)
	}

	switch {
	case pwnCount > 0:
		resCh <- pwCheckResult{
			Index:   pwIndex,
			IsSafe:  false,
			NameStr: nameStr,
			Message: fmt.Sprintf("        [X] %s (updated %s) found in HIBP (Pwned %d times)!", nameStr, pwDateStr, pwnCount),
		}
	case !e.config.CheckAll && password.UpdatedAt <= breachTs:
		resCh <- pwCheckResult{
			Index:   pwIndex,
			IsSafe:  false,
			NameStr: nameStr,
			Message: fmt.Sprintf("        [!] %s (updated %s) is older than the breach (but NOT found in HIBP)!", nameStr, pwDateStr),
		}
	default:
		if !e.config.CheckAll {
			resCh <- pwCheckResult{
				Index:   pwIndex,
				IsSafe:  true,
				NameStr: nameStr,
				Message: fmt.Sprintf("    [+] %s (updated %s) updated AFTER the breach and NOT found in HIBP (safe).", nameStr, pwDateStr),
			}
		} else {
			resCh <- pwCheckResult{
				Index:   pwIndex,
				IsSafe:  true,
				NameStr: nameStr,
				Message: fmt.Sprintf("    [+] %s (updated %s) is NOT found in HIBP (safe).", nameStr, pwDateStr),
			}
		}
	}
}

func (e *Engine) formatResult(results []pwCheckResult, isSafe bool) string {
	var sb strings.Builder

	for _, res := range results {
		if res.IsSafe {
			sb.WriteString(res.Message + "\n")
		}
	}

	if !isSafe {
		sb.WriteString("    \033[31;1m[!] IMMEDIATE ACTION REQUIRED.\033[0m\n")
		for _, res := range results {
			if !res.IsSafe {
				sb.WriteString(res.Message + "\n")
			}
		}
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

		if len(bInfo.DataClasses) == 0 {
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
		leakedData = append(leakedData, strings.Join(bInfo.DataClasses, ", "))
	}
	return
}
