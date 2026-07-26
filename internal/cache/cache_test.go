package cache

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mockTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

type errCloser struct {
	io.Reader
}

func (errCloser) Close() error {
	return errors.New("close error")
}

type mockWriteCloser struct {
	writeErr error
	closeErr error
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	return m.closeErr
}

func TestManager_OptionsAndInit(t *testing.T) {
	tempDir := t.TempDir()

	mgr, err := NewManager(&http.Client{},
		WithCacheDirFunc(func() (string, error) { return tempDir, nil }),
		WithTTL(1*time.Second),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mgr.ttl != 1*time.Second {
		t.Errorf("expected ttl 1s, got %v", mgr.ttl)
	}

	_, err = NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) {
		return "", errors.New("dir error")
	}))
	if err == nil {
		t.Error("expected error on cacheDirFunc error")
	}

	invalidPath := filepath.Join(tempDir, "invalid_dir") + string([]byte{0})
	_, err = NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) {
		return invalidPath, nil
	}))
	if err == nil {
		t.Error("expected error on MkdirAll error")
	}
}

func TestManager_IsCached(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{},
		WithCacheDirFunc(func() (string, error) { return tempDir, nil }),
		WithTTL(2*time.Second),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mgr.IsCached(file2FA) {
		t.Error("expected IsCached false for non-existent file")
	}

	path := filepath.Join(mgr.dir, file2FA)
	if writeErr := os.WriteFile(path, []byte(`{}`), 0o600); writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}

	if !mgr.IsCached(file2FA) {
		t.Error("expected IsCached true for fresh file")
	}

	if chErr := os.Chtimes(path, time.Now().Add(-5*time.Second), time.Now().Add(-5*time.Second)); chErr != nil {
		t.Fatalf("failed to chtimes: %v", chErr)
	}
	if mgr.IsCached(file2FA) {
		t.Error("expected IsCached false for expired file")
	}
}
