package types

import (
	"encoding/json"
	"time"
)

// TunnelAccountPolicy controls account-wide tunnel obfuscation.
type TunnelAccountPolicy string

const (
	TunnelAccountPolicyStandard   TunnelAccountPolicy = "standard"
	TunnelAccountPolicyPreferAWG  TunnelAccountPolicy = "prefer_awg"
	TunnelAccountPolicyRequireAWG TunnelAccountPolicy = "require_awg"
)

// TunnelUserPolicy refines tunnel selection for peers owned by a user.
type TunnelUserPolicy string

const (
	TunnelUserPolicyInherit      TunnelUserPolicy = "inherit"
	TunnelUserPolicyPreferAWG    TunnelUserPolicy = "prefer_awg"
	TunnelUserPolicyStandardOnly TunnelUserPolicy = "standard_only"
)

// TunnelProfile is the active account-wide Hybrid AWG profile.
type TunnelProfile struct {
	ProtocolVersion string          `json:"protocol_version"`
	Revision        uint64          `json:"revision"`
	Parameters      json.RawMessage `json:"parameters"`
	UpdatedAt       time.Time       `json:"updated_at"`
}
