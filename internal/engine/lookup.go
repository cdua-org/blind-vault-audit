package engine

import (
	"net/netip"
	"strings"
)

func lookupDomain[T any](table map[string]T, host string) (matched string, value T, ok bool) {
	cleaned := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if cleaned == "" {
		var zero T
		return "", zero, false
	}
	if val, found := table[cleaned]; found {
		return cleaned, val, true
	}
	if _, err := netip.ParseAddr(cleaned); err == nil {
		var zero T
		return "", zero, false
	}
	cursor := cleaned
	for {
		idx := strings.IndexByte(cursor, '.')
		if idx == -1 {
			break
		}
		cursor = cursor[idx+1:]
		if !strings.ContainsRune(cursor, '.') {
			break
		}
		if val, found := table[cursor]; found {
			return cursor, val, true
		}
	}
	var zero T
	return "", zero, false
}
