package model

import "time"

const (
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusDelivered  = "delivered"
	StatusDead       = "dead"
)

// Integration stores one encrypted event-streaming configuration. Only one
// integration can be enabled for an account at a time.
type Integration struct {
	ID              uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountID       string    `gorm:"not null;uniqueIndex:idx_local_event_stream_account_platform;size:64;index" json:"account_id"`
	Platform        string    `gorm:"not null;uniqueIndex:idx_local_event_stream_account_platform;size:32" json:"platform"`
	Enabled         bool      `gorm:"not null;default:false;index" json:"enabled"`
	EncryptedConfig string    `gorm:"type:text;not null" json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (Integration) TableName() string { return "local_event_stream_integrations" }

// Outbox is the durable hand-off between the activity store and an external
// destination. Payloads remain encrypted while queued or retained for audit.
type Outbox struct {
	ID               string     `gorm:"primaryKey;size:32" json:"id"`
	IntegrationID    uint64     `gorm:"not null;uniqueIndex:idx_local_event_stream_event,priority:1;index" json:"integration_id"`
	AccountID        string     `gorm:"not null;size:64;index" json:"account_id"`
	EventID          uint64     `gorm:"not null;uniqueIndex:idx_local_event_stream_event,priority:2" json:"event_id"`
	EncryptedPayload string     `gorm:"type:text;not null" json:"-"`
	Status           string     `gorm:"not null;size:16;index:idx_local_event_stream_ready,priority:1" json:"status"`
	Attempts         int        `gorm:"not null;default:0" json:"attempts"`
	NextAttemptAt    time.Time  `gorm:"not null;index:idx_local_event_stream_ready,priority:2" json:"next_attempt_at"`
	LeaseOwner       string     `gorm:"size:64;index" json:"-"`
	LeaseUntil       *time.Time `gorm:"index" json:"-"`
	LastError        string     `gorm:"size:512" json:"last_error,omitempty"`
	DeliveredAt      *time.Time `gorm:"index" json:"delivered_at,omitempty"`
	CreatedAt        time.Time  `gorm:"not null;index" json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (Outbox) TableName() string { return "local_event_stream_outbox" }
