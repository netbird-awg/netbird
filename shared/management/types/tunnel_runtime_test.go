package types

import "testing"

func TestNormalizeTunnelReadinessErrorCode(t *testing.T) {
	for _, code := range []string{
		TunnelRuntimeErrorClockSkew,
		TunnelRuntimeErrorProfileInvalid,
		TunnelRuntimeErrorMetadataInvalid,
		TunnelRuntimeErrorMetadataIncomplete,
		TunnelReadinessErrorAdapterIncompatible,
		TunnelReadinessErrorProtocolMismatch,
		TunnelReadinessErrorRevisionMismatch,
		TunnelReadinessErrorNotReady,
	} {
		if got := NormalizeTunnelReadinessErrorCode(code); got != code {
			t.Fatalf("normalize %q = %q", code, got)
		}
	}
	if got := NormalizeTunnelReadinessErrorCode("peer-specific-error"); got != TunnelRuntimeErrorMetadataInvalid {
		t.Fatalf("unknown readiness code = %q", got)
	}
}
