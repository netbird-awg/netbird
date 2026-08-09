package types

const (
	TunnelRuntimeErrorClockSkew             = "clock_skew"
	TunnelRuntimeErrorProfileInvalid        = "profile_invalid"
	TunnelRuntimeErrorMetadataInvalid       = "invalid_runtime_metadata"
	TunnelRuntimeErrorMetadataIncomplete    = "incomplete_runtime_metadata"
	TunnelReadinessErrorAdapterIncompatible = "adapter_incompatible"
	TunnelReadinessErrorProtocolMismatch    = "protocol_mismatch"
	TunnelReadinessErrorRevisionMismatch    = "revision_mismatch"
	TunnelReadinessErrorNotReady            = "not_ready"
)

// NormalizeTunnelRuntimeErrorCode returns an allowlisted stable error code.
func NormalizeTunnelRuntimeErrorCode(code string) string {
	switch code {
	case "",
		TunnelRuntimeErrorClockSkew,
		TunnelRuntimeErrorProfileInvalid,
		TunnelRuntimeErrorMetadataInvalid,
		TunnelRuntimeErrorMetadataIncomplete:
		return code
	default:
		return TunnelRuntimeErrorMetadataInvalid
	}
}

// NormalizeTunnelReadinessErrorCode returns an allowlisted aggregate code.
func NormalizeTunnelReadinessErrorCode(code string) string {
	switch code {
	case TunnelRuntimeErrorClockSkew,
		TunnelRuntimeErrorProfileInvalid,
		TunnelRuntimeErrorMetadataInvalid,
		TunnelRuntimeErrorMetadataIncomplete,
		TunnelReadinessErrorAdapterIncompatible,
		TunnelReadinessErrorProtocolMismatch,
		TunnelReadinessErrorRevisionMismatch,
		TunnelReadinessErrorNotReady:
		return code
	default:
		return TunnelRuntimeErrorMetadataInvalid
	}
}
