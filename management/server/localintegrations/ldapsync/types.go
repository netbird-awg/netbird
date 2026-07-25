package ldapsync

import (
	"time"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
)

type ConfigRequest struct {
	Enabled                  bool                         `json:"enabled"`
	IntervalMinutes          int                          `json:"interval_minutes"`
	SyncScopeGroups          []string                     `json:"sync_scope_groups"`
	GroupMappings            []ldapsyncmodel.GroupMapping `json:"group_mappings"`
	DeprovisionAction        string                       `json:"deprovision_action"`
	ConflictPolicy           string                       `json:"conflict_policy"`
	Revision                 int64                        `json:"revision"`
	AllowWithoutDefaultScope bool                         `json:"allow_without_default_scope,omitempty"`
}

type ConnectorTestResponse struct {
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks"`
	LatencyMS int64             `json:"latency_ms"`
	TestedAt  time.Time         `json:"tested_at"`
}

type ConnectorTestErrorResponse struct {
	Status string            `json:"status"`
	Stage  string            `json:"stage"`
	Code   string            `json:"error_code"`
	Checks map[string]string `json:"checks,omitempty"`
}

type PreviewCounts struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Disabled  int `json:"disabled"`
	Unchanged int `json:"unchanged"`
	Skipped   int `json:"skipped"`
	Conflicts int `json:"conflicts"`
}

type PreviewSample struct {
	Action         string `json:"action"`
	ExternalIDHash string `json:"external_id_hash"`
	Email          string `json:"email,omitempty"`
	Name           string `json:"name,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type PreviewResponse struct {
	Counts              PreviewCounts   `json:"counts"`
	Samples             []PreviewSample `json:"samples"`
	SourceFingerprint   string          `json:"source_fingerprint"`
	HighRisk            bool            `json:"high_risk"`
	HighRiskReason      string          `json:"high_risk_reason,omitempty"`
	ConfirmationToken   string          `json:"confirmation_token,omitempty"`
	ConfirmationExpires *time.Time      `json:"confirmation_expires_at,omitempty"`
}

type RunRequest struct {
	ConfirmationToken string `json:"confirmation_token,omitempty"`
}

type RunListResponse struct {
	Items  []*ldapsyncmodel.Run `json:"items"`
	Total  int64                `json:"total"`
	Offset int                  `json:"offset"`
	Limit  int                  `json:"limit"`
}
