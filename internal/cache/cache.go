// Package cache provides local caching functionality for remote APIs.
package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cdua-org/blind-vault-audit/internal/config"
)

const (
	file2FA      = "2fa_v1.json"
	filePK       = "passkeys_v1.json"
	fileBreaches = "breaches_v1.json"
)

// Manager handles caching files to disk.
type Manager struct {
	client       *http.Client
	cacheDirFunc func() (string, error)
	dir          string
	ttl          time.Duration
}

// Option configures the cache Manager.
type Option func(*Manager)

// WithTTL sets the cache TTL.
func WithTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		m.ttl = ttl
	}
}

// WithCacheDirFunc overrides the function used to determine the cache directory.
func WithCacheDirFunc(f func() (string, error)) Option {
	return func(m *Manager) {
		m.cacheDirFunc = f
	}
}

// NewManager creates a new Manager instance.
func NewManager(client *http.Client, opts ...Option) (*Manager, error) {
	m := &Manager{
		client:       client,
		ttl:          24 * time.Hour,
		cacheDirFunc: os.UserCacheDir,
	}
	for _, opt := range opts {
		opt(m)
	}

	cacheDir, err := m.cacheDirFunc()
	if err != nil {
		return nil, fmt.Errorf("could not get user cache dir: %w", err)
	}
	m.dir = filepath.Join(cacheDir, "bva")
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return nil, fmt.Errorf("could not create cache dir %s: %w", m.dir, err)
	}
	return m, nil
}

// IsCached checks if the given file exists and is within TTL.
func (m *Manager) IsCached(filename string) bool {
	path := filepath.Join(m.dir, filename)
	info, err := os.Stat(path)
	if err == nil {
		if time.Since(info.ModTime()) < m.ttl {
			return true
		}
	}
	return false
}

// Fetch2FA fetches the 2FA database.
func (m *Manager) Fetch2FA(ctx context.Context, force bool) (data []byte, path string, modTime time.Time, cached bool, err error) {
	return m.fetch(ctx, config.Endpoint2FA, file2FA, force)
}

// FetchPK fetches the Passkeys database.
func (m *Manager) FetchPK(ctx context.Context, force bool) (data []byte, path string, modTime time.Time, cached bool, err error) {
	return m.fetch(ctx, config.EndpointPK, filePK, force)
}

// FetchBreaches fetches the Breaches database.
func (m *Manager) FetchBreaches(ctx context.Context, force bool) (data []byte, path string, modTime time.Time, cached bool, err error) {
	return m.fetch(ctx, config.EndpointBreaches, fileBreaches, force)
}

func (m *Manager) fetch(ctx context.Context, url, filename string, force bool) (data []byte, path string, modTime time.Time, cached bool, err error) {
	safeFilename, err := sanitizeFilename(filename)
	if err != nil {
		return nil, "", time.Time{}, false, err
	}

	path = filepath.Join(m.dir, safeFilename)

	if !force {
		info, errStat := os.Stat(path)
		if errStat == nil && time.Since(info.ModTime()) < m.ttl {
			var readErr error
			data, readErr = os.ReadFile(filepath.Clean(path))
			if readErr == nil {
				return data, path, info.ModTime(), true, nil
			}
		}
	}

	return m.downloadAndCache(ctx, url, path)
}

func (m *Manager) downloadAndCache(ctx context.Context, url, path string) (data []byte, retPath string, modTime time.Time, cached bool, err error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if reqErr != nil {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to create request: %w", reqErr)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to execute request: %w", err)
	}

	defer func() {
		if cErr := resp.Body.Close(); cErr != nil && err == nil {
			err = fmt.Errorf("failed to close response body: %w", cErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to fetch %s: status %d", url, resp.StatusCode)
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to read response body: %w", err)
	}

	f, fileErr := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if fileErr != nil {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to open cache file %s: %w", path, fileErr)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return nil, path, time.Time{}, false, fmt.Errorf("failed to write cache file %s", path)
	}

	info, statErr := os.Stat(path)
	if statErr == nil {
		modTime = info.ModTime()
	} else {
		modTime = time.Now()
	}

	return data, path, modTime, false, nil
}

func sanitizeFilename(filename string) (string, error) {
	switch filename {
	case file2FA:
		return file2FA, nil
	case filePK:
		return filePK, nil
	case fileBreaches:
		return fileBreaches, nil
	default:
		return "", fmt.Errorf("invalid cache filename: %s", filename)
	}
}
