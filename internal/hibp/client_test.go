package hibp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func newTestClient() *Client {
	c := NewClient(nil, "")
	c.breachesURL = "https://api.example.com/breaches"
	c.pwnedURL = "https://api.example.com/range/"
	return c
}

func TestFetchBreaches_Success(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	jsonBody := `[
		{"Domain": "", "BreachDate": ""},
		{"Domain": "example.com", "BreachDate": "2015-03-01"},
		{"Domain": "example.net", "BreachDate": "invalid-date"},
		{"Domain": "example.com", "BreachDate": "2016-04-01"}
	]`

	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(jsonBody)),
		}, nil
	}

	client := newTestClient()
	ctx := context.Background()

	result, err := client.FetchBreaches(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 valid domain, got %d", len(result))
	}

	ts, ok := result["example.com"]
	if !ok {
		t.Fatalf("expected example.com in result")
	}

	if ts != 1459468800 {
		t.Errorf("expected timestamp 1459468800, got %d", ts)
	}
}

func TestFetchBreaches_Forbidden(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(bytes.NewBufferString("")),
		}, nil
	}

	client := newTestClient()
	ctx := context.Background()

	_, err := client.FetchBreaches(ctx)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

type errorReadCloser struct {
	io.Reader
}

func (errorReadCloser) Close() error {
	return errors.New("simulated close error")
}

type errorReader struct{}

func (errorReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func (errorReader) Close() error {
	return nil
}

func TestFetchBreaches_Errors(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	client := newTestClient()
	ctx := context.Background()

	t.Run("unexpected_status", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString("")),
			}, nil
		}

		_, err := client.FetchBreaches(ctx)
		if err == nil {
			t.Error("expected error due to unexpected status, got nil")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("{invalid-json")),
			}, nil
		}

		_, err := client.FetchBreaches(ctx)
		if err == nil {
			t.Error("expected error due to invalid JSON, got nil")
		}
	})

	t.Run("create_request_error", func(t *testing.T) {
		errClient := newTestClient()
		errClient.breachesURL = ":\x00"
		_, err := errClient.FetchBreaches(ctx)
		if err == nil {
			t.Error("expected error due to invalid URL, got nil")
		}
	})

	t.Run("close_error", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{bytes.NewBufferString("[]")},
			}, nil
		}

		_, err := client.FetchBreaches(ctx)
		if err != nil {
			t.Errorf("expected no error from FetchBreaches itself, got %v", err)
		}
	})
}

func TestCheckPasswordPwned_Found(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	respBody := "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3300000\r\n00000000000000000000000000000000000:1"

	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(respBody)),
		}, nil
	}

	client := newTestClient()
	ctx := context.Background()

	count, err := client.CheckPasswordPwned(ctx, "password")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 3300000 {
		t.Errorf("expected count 3300000, got %d", count)
	}
}

func TestCheckPasswordPwned_NotFound(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	respBody := "00000000000000000000000000000000000:1"

	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(respBody)),
		}, nil
	}

	client := newTestClient()
	ctx := context.Background()

	count, err := client.CheckPasswordPwned(ctx, "safe_password")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

func TestDoWithRetry_RateLimited(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	calls := 0
	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"0"}},
			Body:       io.NopCloser(bytes.NewBufferString("")),
		}, nil
	}

	client := newTestClient()
	ctx := context.Background()

	_, err := client.FetchBreaches(ctx)
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}

	if calls != 4 {
		t.Errorf("expected 4 calls, got %d", calls)
	}
}

func TestDoWithRetry_Error(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	expectedErr := errors.New("network error")
	doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
		return nil, expectedErr
	}

	client := newTestClient()
	ctx := context.Background()

	_, err := client.FetchBreaches(ctx)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected network error, got %v", err)
	}
}

type mockTransport struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func TestDefaultDoReq(t *testing.T) {
	client := &http.Client{
		Transport: &mockTransport{
			fn: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("ok")),
				}, nil
			},
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := defaultDoReq(context.Background(), client, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Logf("failed to close body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %d", resp.StatusCode)
	}

	clientErr := &http.Client{
		Transport: &mockTransport{
			fn: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("simulated network error")
			},
		},
	}

	respErr, err := defaultDoReq(context.Background(), clientErr, req)
	if err == nil {
		t.Error("expected error due to simulated network error, got nil")
	}
	if respErr != nil && respErr.Body != nil {
		if closeErr := respErr.Body.Close(); closeErr != nil {
			t.Logf("failed to close body: %v", closeErr)
		}
	}
}

func TestCheckPasswordPwned_Errors(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	client := newTestClient()
	ctx := context.Background()

	t.Run("create_request_error", func(t *testing.T) {
		client.pwnedURL = ":\x00"
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil {
			t.Error("expected error due to invalid URL, got nil")
		}
		client.pwnedURL = "https://api.example.com/range/"
	})

	t.Run("unexpected_status", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBufferString("")),
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil {
			t.Error("expected error due to unexpected status, got nil")
		}
	})

	t.Run("close_error", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{bytes.NewBufferString("")},
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err != nil {
			t.Errorf("expected no error from CheckPasswordPwned itself, got %v", err)
		}
	})

	t.Run("empty_password", func(t *testing.T) {
		count, err := client.CheckPasswordPwned(ctx, "")
		if err != nil {
			t.Errorf("expected no error for empty password, got %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 count for empty password, got %d", count)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBufferString("")),
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("network_error", func(t *testing.T) {
		expectedErr := errors.New("network error")
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return nil, expectedErr
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil {
			t.Error("expected error due to network failure, got nil")
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReader{},
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil {
			t.Error("expected error due to body read failure, got nil")
		}
	})

	t.Run("invalid_count", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			hashStr := "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
			suffix := hashStr[5:]

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(suffix + ":invalid-count\r\n")),
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil {
			t.Error("expected error due to invalid count format, got nil")
		}
	})

	t.Run("scanner_error", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(strings.Repeat("a", 65537))),
			}, nil
		}
		_, err := client.CheckPasswordPwned(ctx, "password")
		if err == nil || !strings.Contains(err.Error(), "scanner error") {
			t.Errorf("expected scanner error, got %v", err)
		}
	})
}

func TestDoWithRetry_ContextCanceled_429(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	client := newTestClient()
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	if errReq != nil {
		t.Fatalf("failed to create request: %v", errReq)
	}

	t.Run("429_context_canceled", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       errorReadCloser{bytes.NewBufferString("")},
			}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resp, err := client.doWithRetry(ctx, req)
		if resp != nil && resp.Body != nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Logf("failed to close body: %v", closeErr)
			}
		}
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("expected context canceled error, got %v", err)
		}
	})
}

func TestDoWithRetry_ContextCanceled_500(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	client := newTestClient()
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	if errReq != nil {
		t.Fatalf("failed to create request: %v", errReq)
	}

	t.Run("500_context_canceled", func(t *testing.T) {
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       errorReadCloser{bytes.NewBufferString("")},
			}, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		resp, err := client.doWithRetry(ctx, req)
		if resp != nil && resp.Body != nil {
			defer func() {
				if closeErr := resp.Body.Close(); closeErr != nil {
					t.Logf("failed to close body: %v", closeErr)
				}
			}()
		}
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("expected context canceled error, got %v", err)
		}
	})
}

func TestDoWithRetry_Continue(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	client := newTestClient()
	req, errReq := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	if errReq != nil {
		t.Fatalf("failed to create request: %v", errReq)
	}

	t.Run("500_continue", func(t *testing.T) {
		attempts := 0
		doReq = func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString("")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("")),
			}, nil
		}
		ctx := context.Background()
		resp, err := client.doWithRetry(ctx, req)
		if resp != nil && resp.Body != nil {
			defer func() {
				if closeErr := resp.Body.Close(); closeErr != nil {
					t.Logf("failed to close body: %v", closeErr)
				}
			}()
		}
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})
}
