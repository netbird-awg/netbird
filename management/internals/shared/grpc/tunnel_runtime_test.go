package grpc

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestExtractTunnelRuntimeRejectsIncompleteReadyReport(t *testing.T) {
	runtime := extractTunnelRuntime(&proto.TunnelRuntimeMeta{
		ProtocolVersion: "awg2",
		Ready:           true,
	})

	if runtime.Ready ||
		runtime.ErrorCode != "incomplete_runtime_metadata" {
		t.Fatalf("incomplete ready report was accepted: %+v", runtime)
	}
}

func TestExtractTunnelRuntimeRejectsClockSkew(t *testing.T) {
	runtime := extractTunnelRuntime(&proto.TunnelRuntimeMeta{
		ProtocolVersion:      "awg2",
		ProfileRevision:      7,
		AdapterRevision:      "adapter",
		Ready:                true,
		EstimatedClockSkewMs: 2001,
	})

	if runtime.Ready || runtime.ErrorCode != "clock_skew" {
		t.Fatalf("clock-skewed ready report was accepted: %+v", runtime)
	}
}

func TestExtractTunnelRuntimeAcceptsBoundedReadyReport(t *testing.T) {
	runtime := extractTunnelRuntime(&proto.TunnelRuntimeMeta{
		ProtocolVersion:      "awg2",
		ProfileRevision:      7,
		AdapterRevision:      "adapter",
		Ready:                true,
		EstimatedClockSkewMs: -100,
	})

	if !runtime.Ready || runtime.ErrorCode != "" {
		t.Fatalf("valid ready report was rejected: %+v", runtime)
	}
}
