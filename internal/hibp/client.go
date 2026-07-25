// Package hibp provides a client for interacting with the Have I Been Pwned API.
package hibp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/crypto/hibphash"
)

// API Errors returned by the HIBP client during HTTP requests.
var (
	ErrRateLimited = errors.New("rate limited by HIBP API")
	ErrForbidden   = errors.New("forbidden by HIBP API, possible IP ban or invalid request")
)

// BreachData represents a single breach record returned by the HIBP API.
type BreachData struct {
	Domain     string `json:"Domain"`
	BreachDate string `json:"BreachDate"`
}

// Client interacts with the Have I Been Pwned API.
type Client struct {
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new HIBP Client.
func NewClient(httpClient *http.Client, userAgent string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "Blind-Vault-Audit"
	}
	return &Client{httpClient: httpClient, userAgent: userAgent}
}

var doReq = defaultDoReq

func defaultDoReq(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return resp, nil
}

// FetchBreaches retrieves the list of all breaches and returns a map of domains to their Unix timestamp.
func (c *Client) FetchBreaches(ctx context.Context) (map[string]int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://haveibeenpwned.com/api/v3/breaches", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			_ = err
		}
	}()

	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var breaches []BreachData
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	result := make(map[string]int64, len(breaches))
	for _, b := range breaches {
		domain := strings.TrimSpace(strings.ToLower(b.Domain))
		if domain == "" || b.BreachDate == "" {
			continue
		}

		dt, err := time.Parse("2006-01-02", b.BreachDate)
		if err != nil {
			continue
		}

		ts := dt.Unix()
		if existing, ok := result[domain]; !ok || ts > existing {
			result[domain] = ts
		}
	}

	return result, nil
}

// CheckPasswordPwned hashes the password and uses the k-Anonymity API to check if it has been breached.
func (c *Client) CheckPasswordPwned(ctx context.Context, password string) (int, error) {
	if password == "" {
		return 0, nil
	}

	hashStr := hibphash.HashPassword(password)
	prefix, suffix := hashStr[:5], hashStr[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, http.NoBody)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Add-Padding", "true")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode == http.StatusForbidden {
		return 0, ErrForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 && parts[0] == suffix {
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return 0, fmt.Errorf("failed to parse count: %w", err)
			}
			return count, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scanner error: %w", err)
	}

	return 0, nil
}

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i <= maxRetries; i++ {
		resp, err = doReq(ctx, c.httpClient, req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			waitDuration := backoff
			if retryAfter != "" {
				if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
					waitDuration = time.Duration(seconds) * time.Second
				}
			}

			if closeErr := resp.Body.Close(); closeErr != nil {
				_ = closeErr
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
			case <-time.After(waitDuration):
				continue
			}
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			if err := resp.Body.Close(); err != nil {
				_ = err
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context canceled during backoff: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
				continue
			}
		}

		return resp, nil
	}

	return nil, ErrRateLimited
}
