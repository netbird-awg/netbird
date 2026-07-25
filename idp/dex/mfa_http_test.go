package dex

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingMFAAttemptLimiter struct {
	failures int
	clears   int
}

func (l *recordingMFAAttemptLimiter) Check(context.Context, string, string) (time.Duration, error) {
	return 0, nil
}

func (l *recordingMFAAttemptLimiter) RecordFailure(context.Context, string, string) error {
	l.failures++
	return nil
}

func (l *recordingMFAAttemptLimiter) Clear(context.Context, string, string) error {
	l.clears++
	return nil
}

func TestUpdateMFAAttemptState(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		expectedFailures int
		expectedClears   int
	}{
		{
			name:             "invalid TOTP returned as unauthorized",
			statusCode:       http.StatusUnauthorized,
			expectedFailures: 1,
		},
		{
			name:             "legacy failed form returned as OK",
			statusCode:       http.StatusOK,
			expectedFailures: 1,
		},
		{
			name:           "successful verification redirect",
			statusCode:     http.StatusSeeOther,
			expectedClears: 1,
		},
		{
			name:       "unrelated client error",
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := &recordingMFAAttemptLimiter{}
			provider := &Provider{
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			provider.updateMFAAttemptState(context.Background(), limiter, "user", "openldap", tt.statusCode)

			require.Equal(t, tt.expectedFailures, limiter.failures)
			require.Equal(t, tt.expectedClears, limiter.clears)
		})
	}
}
