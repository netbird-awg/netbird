package model

import "time"

const (
	ConfigMinIntervalMinutes = 5
	ConfigMaxIntervalMinutes = 1440
	DefaultScopeGroup        = "netbird"

	DeprovisionDisable = "disable"
	DeprovisionIgnore  = "ignore"
	ConflictSkip       = "skip"

	RunStatusQueued           = "queued"
	RunStatusAwaitingApproval = "awaiting_approval"
	RunStatusRunning          = "running"
	RunStatusSuccess          = "success"
	RunStatusPartial          = "partial"
	RunStatusFailed           = "failed"
	RunStatusCancelled        = "cancelled"

	RunTriggerManual    = "manual"
	RunTriggerScheduled = "scheduled"
	RunTriggerInitial   = "initial"

	ObjectTypeUser  = "user"
	ObjectTypeGroup = "group"

	ObjectStatusActive   = "active"
	ObjectStatusDisabled = "disabled"
)

// GroupMapping maps an LDAP group name to existing NetBird Auto Groups.
type GroupMapping struct {
	LDAPGroup           string   `json:"ldap_group"`
	NetBirdAutoGroupIDs []string `json:"netbird_auto_group_ids"`
}

// Config stores synchronization policy only. LDAP connection/search settings
// remain owned by the referenced Identity Provider connector.
type Config struct {
	ID                uint64         `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountID         string         `gorm:"not null;uniqueIndex:idx_local_ldap_sync_config_account_connector;size:64" json:"account_id"`
	ConnectorID       string         `gorm:"not null;uniqueIndex:idx_local_ldap_sync_config_account_connector;size:255" json:"connector_id"`
	Enabled           bool           `gorm:"not null;default:false" json:"enabled"`
	IntervalMinutes   int            `gorm:"not null;default:60" json:"interval_minutes"`
	SyncScopeGroups   []string       `gorm:"serializer:json" json:"sync_scope_groups"`
	GroupMappings     []GroupMapping `gorm:"serializer:json" json:"group_mappings"`
	DeprovisionAction string         `gorm:"not null;default:disable;size:32" json:"deprovision_action"`
	ConflictPolicy    string         `gorm:"not null;default:skip;size:32" json:"conflict_policy"`
	FailureCount      int            `gorm:"not null;default:0" json:"failure_count"`
	PausedReason      string         `gorm:"size:255" json:"paused_reason,omitempty"`
	NextRunAt         *time.Time     `gorm:"index" json:"next_run_at,omitempty"`
	LastSuccessAt     *time.Time     `json:"last_success_at,omitempty"`
	Revision          int64          `gorm:"not null;default:1" json:"revision"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func (Config) TableName() string { return "local_ldap_sync_configs" }

// Run is both the durable PostgreSQL work queue row and the immutable summary
// shown in run history.
type Run struct {
	ID                    string     `gorm:"primaryKey;size:32" json:"id"`
	AccountID             string     `gorm:"not null;index:idx_local_ldap_sync_runs_account_connector_created,priority:1;uniqueIndex:idx_local_ldap_sync_active_run,priority:1,where:status = 'queued' OR status = 'awaiting_approval' OR status = 'running';size:64" json:"account_id"`
	ConnectorID           string     `gorm:"not null;index:idx_local_ldap_sync_runs_account_connector_created,priority:2;uniqueIndex:idx_local_ldap_sync_active_run,priority:2,where:status = 'queued' OR status = 'awaiting_approval' OR status = 'running';size:255" json:"connector_id"`
	Status                string     `gorm:"not null;index;size:32" json:"status"`
	Trigger               string     `gorm:"not null;size:32" json:"trigger"`
	InitiatedBy           string     `gorm:"size:64" json:"initiated_by,omitempty"`
	ConfigRevision        int64      `gorm:"not null" json:"config_revision"`
	SourceFingerprint     string     `gorm:"size:64" json:"source_fingerprint,omitempty"`
	ConfirmationTokenHash string     `gorm:"size:64" json:"-"`
	ConfirmationExpiresAt *time.Time `json:"confirmation_expires_at,omitempty"`
	QueuedAt              time.Time  `gorm:"not null;index" json:"queued_at"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	FinishedAt            *time.Time `json:"finished_at,omitempty"`
	LeaseUntil            *time.Time `gorm:"index" json:"-"`
	LeaseOwner            string     `gorm:"size:64;index" json:"-"`
	Attempt               int        `gorm:"not null;default:0" json:"attempt"`
	CreatedCount          int        `gorm:"not null;default:0" json:"created_count"`
	UpdatedCount          int        `gorm:"not null;default:0" json:"updated_count"`
	DisabledCount         int        `gorm:"not null;default:0" json:"disabled_count"`
	SkippedCount          int        `gorm:"not null;default:0" json:"skipped_count"`
	ConflictCount         int        `gorm:"not null;default:0" json:"conflict_count"`
	ErrorCount            int        `gorm:"not null;default:0" json:"error_count"`
	ErrorCode             string     `gorm:"size:64" json:"error_code,omitempty"`
	ErrorSummary          string     `gorm:"size:1024" json:"error_summary,omitempty"`
	CreatedAt             time.Time  `gorm:"index:idx_local_ldap_sync_runs_account_connector_created,priority:3,sort:desc" json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func (Run) TableName() string { return "local_ldap_sync_runs" }

// Object records which NetBird object is managed by which LDAP source object.
type Object struct {
	ID                uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountID         string    `gorm:"not null;uniqueIndex:idx_local_ldap_sync_object_source,priority:1;index:idx_local_ldap_sync_object_target,priority:1;size:64" json:"account_id"`
	ConnectorID       string    `gorm:"not null;uniqueIndex:idx_local_ldap_sync_object_source,priority:2;index:idx_local_ldap_sync_object_target,priority:2;size:255" json:"connector_id"`
	ObjectType        string    `gorm:"not null;uniqueIndex:idx_local_ldap_sync_object_source,priority:3;index:idx_local_ldap_sync_object_target,priority:3;size:16" json:"object_type"`
	ExternalID        string    `gorm:"not null;uniqueIndex:idx_local_ldap_sync_object_source,priority:4;size:64" json:"external_id"`
	NetBirdObjectID   string    `gorm:"column:netbird_object_id;not null;index:idx_local_ldap_sync_object_target,priority:4;size:255" json:"netbird_object_id"`
	SourceFingerprint string    `gorm:"size:64" json:"source_fingerprint"`
	LastSeenAt        time.Time `gorm:"index" json:"last_seen_at"`
	ManagedFields     []string  `gorm:"serializer:json" json:"managed_fields"`
	Status            string    `gorm:"not null;size:32" json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (Object) TableName() string { return "local_ldap_sync_objects" }
