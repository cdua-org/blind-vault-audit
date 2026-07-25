package hibp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestFetchBreaches_Success(t *testing.T) {
	originalDoReq := doReq
	defer func() { doReq = originalDoReq }()

	jsonBody := `[
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

	client := NewClient(nil, "")
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

	client := NewClient(nil, "")
	ctx := context.Background()

	_, err := client.FetchBreaches(ctx)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
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

	client := NewClient(nil, "")
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

	client := NewClient(nil, "")
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

	client := NewClient(nil, "")
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

	client := NewClient(nil, "")
	ctx := context.Background()

	_, err := client.FetchBreaches(ctx)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected network error, got %v", err)
	}
}
