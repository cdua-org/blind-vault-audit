package engine

import (
	"testing"
)

func TestLookupDomain(t *testing.T) {
	table := map[string]int{
		"exact.example.com":    1,
		"apex.example.net":     2,
		"auth.sso.example.net": 3,
		"sub.sso.example.org":  4,
		"suite.portal.example": 5,
		"10.0.0.1":             6,
		"::2":                  7,
		"internal":             8,
		"upper.example.org":    9,
		"trail.example.net":    10,
	}

	tests := []struct {
		name      string
		host      string
		wantKey   string
		wantVal   int
		wantFound bool
	}{
		{
			name:      "empty host",
			host:      "",
			wantFound: false,
		},
		{
			name:      "whitespace host",
			host:      "   ",
			wantFound: false,
		},
		{
			name:      "exact match apex domain",
			host:      "exact.example.com",
			wantVal:   1,
			wantFound: true,
		},
		{
			name:      "exact match subdomain",
			host:      "auth.sso.example.net",
			wantVal:   3,
			wantFound: true,
		},
		{
			name:      "subdomain fallback to apex",
			host:      "mail.apex.example.net",
			wantKey:   "apex.example.net",
			wantVal:   2,
			wantFound: true,
		},
		{
			name:      "nested subdomain fallback to specific subdomain",
			host:      "api.sub.sso.example.org",
			wantKey:   "sub.sso.example.org",
			wantVal:   4,
			wantFound: true,
		},
		{
			name:      "case insensitivity and whitespace trim",
			host:      "  UPPER.Example.ORG  ",
			wantKey:   "upper.example.org",
			wantVal:   9,
			wantFound: true,
		},
		{
			name:      "trailing dot handling",
			host:      "trail.example.net.",
			wantKey:   "trail.example.net",
			wantVal:   10,
			wantFound: true,
		},
		{
			name:      "ipv4 address exact match",
			host:      "10.0.0.1",
			wantVal:   6,
			wantFound: true,
		},
		{
			name:      "ipv4 address without match does not walk octets",
			host:      "10.0.0.2",
			wantFound: false,
		},
		{
			name:      "ipv6 address exact match",
			host:      "::2",
			wantVal:   7,
			wantFound: true,
		},
		{
			name:      "reserved example tld subdomain",
			host:      "leaf.suite.portal.example",
			wantKey:   "suite.portal.example",
			wantVal:   5,
			wantFound: true,
		},
		{
			name:      "single label exact match",
			host:      "internal",
			wantVal:   8,
			wantFound: true,
		},
		{
			name:      "single label not in table",
			host:      "example",
			wantFound: false,
		},
		{
			name:      "subdomain does not fall back to single label",
			host:      "sub.internal",
			wantFound: false,
		},
		{
			name:      "unknown domain",
			host:      "unknown.example.org",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotVal, gotFound := lookupDomain(table, tt.host)
			if gotFound != tt.wantFound {
				t.Fatalf("lookupDomain(%q) found = %v, want %v", tt.host, gotFound, tt.wantFound)
			}
			expectedKey := tt.wantKey
			if expectedKey == "" && tt.wantFound {
				expectedKey = tt.host
			}
			if gotKey != expectedKey {
				t.Errorf("lookupDomain(%q) key = %q, want %q", tt.host, gotKey, expectedKey)
			}
			if gotVal != tt.wantVal {
				t.Errorf("lookupDomain(%q) val = %d, want %d", tt.host, gotVal, tt.wantVal)
			}
		})
	}
}
