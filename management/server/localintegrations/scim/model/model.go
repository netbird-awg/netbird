package model

import "time"

const (
	ResourceTypeUser  = "user"
	ResourceTypeGroup = "group"

	IntegrationType = "local_scim"
)

// Integration stores the local Generic SCIM synchronization configuration.
// Bearer tokens are never persisted; only their SHA-256 digest and a display
// hint are stored.
type Integration struct {
	ID                uint64     `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountID         string     `gorm:"not null;uniqueIndex:idx_local_scim_account_provider;size:64" json:"account_id"`
	Provider          string     `gorm:"not null;uniqueIndex:idx_local_scim_account_provider;size:32" json:"provider"`
	Prefix            string     `gorm:"size:255" json:"prefix"`
	TokenHash         string     `gorm:"not null;uniqueIndex;size:64" json:"-"`
	TokenHint         string     `gorm:"not null;size:16" json:"-"`
	Enabled           bool       `gorm:"not null;default:true" json:"enabled"`
	GroupPrefixes     []string   `gorm:"serializer:json" json:"group_prefixes"`
	UserGroupPrefixes []string   `gorm:"serializer:json" json:"user_group_prefixes"`
	ConnectorID       string     `gorm:"size:255" json:"connector_id,omitempty"`
	LastSyncedAt      *time.Time `json:"last_synced_at,omitempty"`
	PendingAt         *time.Time `gorm:"index" json:"-"`
	NextAttemptAt     *time.Time `gorm:"index" json:"-"`
	SyncRevision      int64      `gorm:"not null;default:0" json:"-"`
	FailureCount      int        `gorm:"not null;default:0" json:"-"`
	LeaseUntil        *time.Time `gorm:"index" json:"-"`
	LeaseOwner        string     `gorm:"size:64;index" json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (Integration) TableName() string { return "local_scim_integrations" }

// Resource stores an encrypted SCIM User or Group document. Lookup fields are
// keyed hashes so common SCIM equality filters do not require plaintext
// identity data in database columns.
type Resource struct {
	ID                string    `gorm:"primaryKey;size:64" json:"id"`
	IntegrationID     uint64    `gorm:"not null;index:idx_local_scim_resource_integration_type,priority:1;index:idx_local_scim_resource_external,priority:1;index:idx_local_scim_resource_username,priority:1" json:"integration_id"`
	ResourceType      string    `gorm:"not null;index:idx_local_scim_resource_integration_type,priority:2;index:idx_local_scim_resource_external,priority:2;index:idx_local_scim_resource_username,priority:2;size:16" json:"resource_type"`
	ExternalIDHash    string    `gorm:"index:idx_local_scim_resource_external,priority:3;size:64" json:"-"`
	UserNameHash      string    `gorm:"index:idx_local_scim_resource_username,priority:3;size:64" json:"-"`
	EncryptedPayload  string    `gorm:"type:text;not null" json:"-"`
	NetBirdObjectID   string    `gorm:"size:255;index" json:"netbird_object_id,omitempty"`
	Deleted           bool      `gorm:"not null;default:false;index" json:"deleted"`
	SourceFingerprint string    `gorm:"size:64" json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (Resource) TableName() string { return "local_scim_resources" }

// SyncLog is a sanitized operational record shown by the existing Dashboard.
type SyncLog struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	IntegrationID uint64    `gorm:"not null;index:idx_local_scim_logs_integration_created,priority:1" json:"integration_id"`
	Level         string    `gorm:"not null;size:16" json:"level"`
	Message       string    `gorm:"not null;size:512" json:"message"`
	CreatedAt     time.Time `gorm:"index:idx_local_scim_logs_integration_created,priority:2,sort:desc" json:"timestamp"`
}

func (SyncLog) TableName() string { return "local_scim_sync_logs" }

// SyncResult is persisted atomically with lease release. ClaimedRevision in
// the store call prevents a worker from clearing a newer event.
type SyncResult struct {
	Succeeded     bool
	SyncedAt      time.Time
	NextAttemptAt *time.Time
	ErrorSummary  string
}
