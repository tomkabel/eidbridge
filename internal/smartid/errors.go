package smartid

import (
	"errors"
	"fmt"
	"time"
)

// Reason codes. They match the flow state machine in architecture ADR-002.
const (
	ReasonRefused            = "refused"
	ReasonExpired            = "expired"
	ReasonWrongCode          = "wrong_code"
	ReasonAccountUnusable    = "account_unusable"
	ReasonUpstreamError      = "upstream_error"
	ReasonVerificationFailed = "verification_failed"
	ReasonIdentityMismatch   = "identity_mismatch"
	ReasonUnknownEndResult   = "unknown_end_result"
	ReasonStatusUnavailable  = "status_unavailable"
	ReasonRetriesExhausted   = "retries_exhausted"
)

// Error is a typed, fail-closed outcome. Detail never contains personal data
// or secrets; it names the failed check.
type Error struct {
	Reason string
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("smartid: %s: %s: %v", e.Reason, e.Detail, e.Cause)
	}
	return fmt.Sprintf("smartid: %s: %s", e.Reason, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

func fail(reason, detail string) error { return &Error{Reason: reason, Detail: detail} }

func vfail(detail string) error { return &Error{Reason: ReasonVerificationFailed, Detail: detail} }

// ReasonOf returns the reason code of err, or upstream_error for untyped errors.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	var h *HTTPError
	if errors.As(err, &h) {
		if h.Status == 404 {
			return ReasonExpired
		}
		return ReasonUpstreamError
	}
	return ReasonUpstreamError
}

// HTTPError is an RP API transport outcome. Retryable is true for 429, 5xx
// (including 580 maintenance) and network errors; 4xx other than 429 can
// never succeed on retry.
type HTTPError struct {
	Status     int // 0 for network errors
	RetryAfter time.Duration
	Retryable  bool
	Cause      error
}

func (e *HTTPError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("smartid: transport: %v", e.Cause)
	}
	return fmt.Sprintf("smartid: http %d", e.Status)
}

func (e *HTTPError) Unwrap() error { return e.Cause }
