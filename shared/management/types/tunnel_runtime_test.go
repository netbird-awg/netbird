package types

import "testing"

func TestNormalizeTunnelRuntimeErrorCode(t *testing.T) {
	for _, code := range []string{
		"",
		TunnelRuntimeErrorClockSkew,
		TunnelRuntimeErrorProfileInvalid,
		TunnelRuntimeErrorMetadataInvalid,
		TunnelRuntimeErrorMetadataIncomplete,
	} {
		if got := NormalizeTunnelRuntimeErrorCode(code); got != code {
			t.Fatalf("normalize %q = %q", code, got)
		}
	}
	for _, code := range []string{
		"peer-specific-error",
		TunnelReadinessErrorAdapterIncompatible,
		TunnelReadinessErrorProtocolMismatch,
		TunnelReadinessErrorRevisionMismatch,
		TunnelReadinessErrorNotReady,
	} {
		if got := NormalizeTunnelRuntimeErrorCode(code); got != TunnelRuntimeErrorMetadataInvalid {
			t.Fatalf("normalize unknown %q = %q", code, got)
		}
	}
}
