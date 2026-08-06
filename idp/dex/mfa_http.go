package dex

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	if r.statusCode != 0 {
		return
	}
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	return r.ResponseWriter.Write(body)
}

func (p *Provider) attemptLimiter() MFAAttemptLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mfaLimiter
}

func (p *Provider) serveDexWithMFAState(w http.ResponseWriter, r *http.Request) {
	ctx := withMFARequestState(r.Context())
	r = r.WithContext(ctx)

	limiter := p.attemptLimiter()
	if limiter == nil || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/mfa/totp") {
		p.dexServer.ServeHTTP(w, r)
		return
	}

	requestID := r.FormValue("req")
	if requestID == "" || r.FormValue("totp") == "" {
		p.dexServer.ServeHTTP(w, r)
		return
	}

	if _, err := p.storage.GetAuthRequest(ctx, requestID); err != nil {
		p.logger.ErrorContext(ctx, "failed to load MFA request for rate limiting", "error", err)
		http.Error(w, "Unable to verify MFA request.", http.StatusInternalServerError)
		return
	}
	userID, connectorID, _ := currentMFAIdentity(ctx)
	if userID == "" || connectorID == "" {
		p.logger.ErrorContext(ctx, "MFA request identity is unavailable")
		http.Error(w, "Unable to verify MFA request.", http.StatusInternalServerError)
		return
	}

	retryAfter, err := limiter.Check(ctx, userID, connectorID)
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to check MFA rate limit", "error", err)
		http.Error(w, "Unable to verify MFA request.", http.StatusInternalServerError)
		return
	}
	if retryAfter > 0 {
		seconds := int(math.Ceil(retryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		http.Error(w, "Too many MFA attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	recorder := &statusRecorder{ResponseWriter: w}
	p.dexServer.ServeHTTP(recorder, r)
	p.updateMFAAttemptState(ctx, limiter, userID, connectorID, recorder.statusCode)
}

func (p *Provider) updateMFAAttemptState(ctx context.Context, limiter MFAAttemptLimiter, userID, connectorID string, statusCode int) {
	if statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest {
		if err := limiter.Clear(context.WithoutCancel(ctx), userID, connectorID); err != nil {
			p.logger.ErrorContext(ctx, "failed to clear MFA rate limit", "error", err)
		}
		return
	}

	// Dex currently returns 401 for an invalid TOTP. Keep 200 for backwards
	// compatibility with Dex versions that render the failed form as a normal
	// response.
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusOK {
		if err := limiter.RecordFailure(context.WithoutCancel(ctx), userID, connectorID); err != nil {
			p.logger.ErrorContext(ctx, "failed to record MFA verification failure", "error", err)
		}
		return
	}

	p.logger.DebugContext(ctx, "MFA response did not change rate limit state", "status", statusCode)
}
