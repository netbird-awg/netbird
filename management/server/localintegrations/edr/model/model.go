package model

import "time"

// Integration stores one provider configuration. Credentials and match
// attributes are kept together in EncryptedConfig and are never returned by
// the API.
type Integration struct {
	ID              uint64     `gorm:"primaryKey;autoIncrement"`
	AccountID       string     `gorm:"not null;size:64;uniqueIndex:idx_local_edr_account_provider;index"`
	Provider        string     `gorm:"not null;size:32;uniqueIndex:idx_local_edr_account_provider"`
	CreatedBy       string     `gorm:"not null;size:64"`
	Enabled         bool       `gorm:"not null;default:false;index"`
	Groups          []string   `gorm:"serializer:json;type:jsonb;not null"`
	EncryptedConfig string     `gorm:"type:text;not null"`
	LastSyncedAt    *time.Time `gorm:"index"`
	StaleNotifiedAt *time.Time `gorm:"index"`
	NextSyncAt      time.Time  `gorm:"not null;index"`
	LeaseOwner      string     `gorm:"size:64;index"`
	LeaseUntil      *time.Time `gorm:"index"`
	FailureCount    int        `gorm:"not null;default:0"`
	LastError       string     `gorm:"size:512"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (Integration) TableName() string { return "local_edr_integrations" }

// Device is the normalized, minimum device state needed to decide whether a
// NetBird peer is compliant. Vendor payloads are deliberately not retained.
type Device struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement"`
	IntegrationID uint64    `gorm:"not null;uniqueIndex:idx_local_edr_device_external,priority:1;index"`
	AccountID     string    `gorm:"not null;size:64;index"`
	ExternalID    string    `gorm:"not null;size:256;uniqueIndex:idx_local_edr_device_external,priority:2"`
	SerialNumber  string    `gorm:"size:256;index"`
	Hostname      string    `gorm:"size:512;index"`
	Compliant     bool      `gorm:"not null;default:false;index"`
	Reason        string    `gorm:"size:512"`
	LastSeenAt    time.Time `gorm:"index"`
	SyncedAt      time.Time `gorm:"not null;index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (Device) TableName() string { return "local_edr_devices" }

// Bypass records an explicit administrative exception for a peer. It is
// removed automatically as soon as the matched device becomes compliant.
type Bypass struct {
	AccountID string    `gorm:"primaryKey;size:64"`
	PeerID    string    `gorm:"primaryKey;size:64"`
	CreatedBy string    `gorm:"not null;size:64"`
	CreatedAt time.Time `gorm:"not null"`
}

func (Bypass) TableName() string { return "local_edr_bypasses" }
