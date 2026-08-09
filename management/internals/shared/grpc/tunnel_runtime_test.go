package grpc

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
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

func TestExtractTunnelRuntimeClockSkewBoundaries(t *testing.T) {
	for _, skewMS := range []int64{-300001, -300000, 300000, 300001} {
		runtime := extractTunnelRuntime(&proto.TunnelRuntimeMeta{
			ProtocolVersion:      "awg2",
			ProfileRevision:      7,
			AdapterRevision:      "adapter",
			Ready:                true,
			EstimatedClockSkewMs: skewMS,
		})

		overLimit := skewMS < -300000 || skewMS > 300000
		if overLimit &&
			(runtime.Ready ||
				runtime.ErrorCode != sharedtypes.TunnelRuntimeErrorClockSkew) {
			t.Fatalf("clock-skewed ready report was accepted: %+v", runtime)
		}
		if !overLimit && (!runtime.Ready || runtime.ErrorCode != "") {
			t.Fatalf("bounded ready report was rejected: %+v", runtime)
		}
	}
}

func TestExtractTunnelRuntimeNormalizesErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "clock skew",
			code: sharedtypes.TunnelRuntimeErrorClockSkew,
			want: sharedtypes.TunnelRuntimeErrorClockSkew,
		},
		{
			name: "profile invalid",
			code: sharedtypes.TunnelRuntimeErrorProfileInvalid,
			want: sharedtypes.TunnelRuntimeErrorProfileInvalid,
		},
		{
			name: "unknown",
			code: "internal decoder detail",
			want: sharedtypes.TunnelRuntimeErrorMetadataInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := extractTunnelRuntime(&proto.TunnelRuntimeMeta{
				ProtocolVersion: "awg2",
				ProfileRevision: 7,
				AdapterRevision: "adapter",
				Ready:           true,
				ErrorCode:       test.code,
			})
			if runtime.Ready || runtime.ErrorCode != test.want {
				t.Fatalf(
					"normalized runtime = %+v, want code %q",
					runtime,
					test.want,
				)
			}
		})
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
