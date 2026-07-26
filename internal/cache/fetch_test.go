package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdua-org/blind-vault-audit/internal/config"
	"github.com/cdua-org/blind-vault-audit/internal/testdata"
)

func TestManager_Fetch2FA_And_Cache(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == config.Endpoint2FA {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(testdata.Fixture2FA)),
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()

	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, _, _, cached, err := mgr.Fetch2FA(context.Background(), false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cached {
		t.Errorf("expected cached to be false on first fetch")
	}
	if !bytes.Equal(data, testdata.Fixture2FA) {
		t.Errorf("expected data mismatch")
	}

	data2, _, _, cached2, err := mgr.Fetch2FA(context.Background(), false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !cached2 {
		t.Errorf("expected cached to be true on second fetch")
	}
	if !bytes.Equal(data2, data) {
		t.Errorf("cached data mismatch")
	}

	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		},
	}

	data3, _, _, _, err := mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Fatalf("expected error on 500 response, got nil")
	}
	if data3 != nil {
		t.Errorf("expected nil data on error")
	}

	content, err := os.ReadFile(filepath.Clean(filepath.Join(tempDir, "bva", file2FA)))
	if err != nil {
		t.Fatalf("expected no error reading cache, got %v", err)
	}
	if !bytes.Equal(content, testdata.Fixture2FA) {
		t.Errorf("expected cache to remain intact")
	}
}

func TestManager_FetchPK(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == config.EndpointPK {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(testdata.FixturePasskeys)),
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()

	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, _, _, cached, err := mgr.FetchPK(context.Background(), false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cached {
		t.Errorf("expected cached to be false on first fetch")
	}
	if !bytes.Equal(data, testdata.FixturePasskeys) {
		t.Errorf("expected data mismatch")
	}
}

func TestManager_FetchBreaches(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == config.EndpointBreaches {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _, _, cached, err := mgr.FetchBreaches(context.Background(), false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cached {
		t.Errorf("expected cached to be false")
	}
	if string(data) != `{}` {
		t.Errorf("data mismatch")
	}
}

func TestManager_FetchErrors(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, _, _, _, err = mgr.fetch(context.Background(), "", "invalid_file.json", false)
	if err == nil {
		t.Error("expected error for invalid filename")
	}

	_, _, _, _, err = mgr.fetch(context.Background(), "://invalid-url", file2FA, true)
	if err == nil {
		t.Error("expected error for nil context")
	}

	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		},
	}
	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error from client.Do")
	}

	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(errReader{}),
			}, nil
		},
	}
	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error reading body")
	}

	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errCloser{bytes.NewReader([]byte(`{}`))},
			}, nil
		},
	}
	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error closing body")
	}

	http.DefaultTransport = origTransport
}

func TestManager_FileWriteError(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}, nil
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(mgr.dir, file2FA)
	if mkErr := os.Mkdir(path, 0o750); mkErr != nil {
		t.Fatalf("failed to mkdir: %v", mkErr)
	}

	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error writing file due to directory conflict")
	}
}

func TestManager_StatError(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}, nil
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	osStat = func(_ string) (os.FileInfo, error) {
		return nil, errors.New("mock stat error")
	}
	defer func() { osStat = defaultOSStat }()

	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err != nil {
		t.Fatalf("expected no error on stat failure, got %v", err)
	}
}

func TestManager_WriteError(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}, nil
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	osOpenFile = func(_ string, _ int, _ os.FileMode) (io.WriteCloser, error) {
		return &mockWriteCloser{writeErr: errors.New("mock write error")}, nil
	}
	defer func() { osOpenFile = defaultOSOpenFile }()

	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error on write failure")
	}
}

func TestManager_CloseError(t *testing.T) {
	origTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTrip: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}, nil
		},
	}
	defer func() { http.DefaultTransport = origTransport }()

	tempDir := t.TempDir()
	mgr, err := NewManager(&http.Client{}, WithCacheDirFunc(func() (string, error) { return tempDir, nil }))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	osOpenFile = func(_ string, _ int, _ os.FileMode) (io.WriteCloser, error) {
		return &mockWriteCloser{closeErr: errors.New("mock close error")}, nil
	}
	defer func() { osOpenFile = defaultOSOpenFile }()

	_, _, _, _, err = mgr.Fetch2FA(context.Background(), true)
	if err == nil {
		t.Error("expected error on close failure")
	}
}
