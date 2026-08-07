package types

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/netbirdio/netbird/util/crypt"
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

const (
	TunnelProtocolAmneziaWG2 = "awg2"
	TunnelProtocolAmneziaWG3 = "awg3"
)

// TunnelProfileAction requests a state transition for a staged profile.
type TunnelProfileAction string

const (
	TunnelProfileActionActivate TunnelProfileAction = "activate"
	TunnelProfileActionRollback TunnelProfileAction = "rollback"
)

// TunnelProfile is the active account-wide Hybrid AWG profile.
type TunnelProfile struct {
	ProtocolVersion              string          `json:"protocol_version"`
	Revision                     uint64          `json:"revision"`
	Parameters                   json.RawMessage `json:"parameters"`
	EncryptedHeaderProtectionKey string          `json:"encrypted_header_protection_key,omitempty"`
	UpdatedAt                    time.Time       `json:"updated_at"`
	HeaderProtectionKey          []byte          `json:"-" gorm:"-"`
}

// Copy returns an independent copy of the tunnel profile.
func (p *TunnelProfile) Copy() *TunnelProfile {
	if p == nil {
		return nil
	}
	return &TunnelProfile{
		ProtocolVersion:              p.ProtocolVersion,
		Revision:                     p.Revision,
		Parameters:                   slices.Clone(p.Parameters),
		EncryptedHeaderProtectionKey: p.EncryptedHeaderProtectionKey,
		UpdatedAt:                    p.UpdatedAt,
		HeaderProtectionKey:          slices.Clone(p.HeaderProtectionKey),
	}
}

// EncryptSensitiveData encrypts and clears the in-memory AWG3 header key.
func (p *TunnelProfile) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if p == nil {
		return nil
	}
	switch p.ProtocolVersion {
	case TunnelProtocolAmneziaWG2:
		if len(p.HeaderProtectionKey) != 0 ||
			p.EncryptedHeaderProtectionKey != "" {
			return errors.New("AWG2 profile contains an AWG3 header key")
		}
		return nil
	case TunnelProtocolAmneziaWG3:
		if len(p.HeaderProtectionKey) == 0 {
			if p.EncryptedHeaderProtectionKey == "" {
				return errors.New("AWG3 header protection key is missing")
			}
			return nil
		}
	default:
		return fmt.Errorf("unsupported tunnel protocol %q", p.ProtocolVersion)
	}
	if len(p.HeaderProtectionKey) != 32 {
		return fmt.Errorf(
			"AWG3 header protection key must be 32 bytes, got %d",
			len(p.HeaderProtectionKey),
		)
	}
	if enc == nil {
		return errors.New("datastore encryption key is required for AWG3")
	}
	plaintext := base64.StdEncoding.EncodeToString(p.HeaderProtectionKey)
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt AWG3 header protection key: %w", err)
	}
	p.EncryptedHeaderProtectionKey = ciphertext
	p.HeaderProtectionKey = nil
	return nil
}

// DecryptSensitiveData decrypts the persisted AWG3 header key into memory.
func (p *TunnelProfile) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if p == nil {
		return nil
	}
	switch p.ProtocolVersion {
	case TunnelProtocolAmneziaWG2:
		if p.EncryptedHeaderProtectionKey != "" {
			return errors.New("AWG2 profile contains an AWG3 header key")
		}
		return nil
	case TunnelProtocolAmneziaWG3:
		if p.EncryptedHeaderProtectionKey == "" {
			if len(p.HeaderProtectionKey) == 32 {
				return nil
			}
			return errors.New("AWG3 header protection key is missing")
		}
	default:
		return fmt.Errorf("unsupported tunnel protocol %q", p.ProtocolVersion)
	}
	if enc == nil {
		return errors.New("datastore encryption key is required for AWG3")
	}
	plaintext, err := enc.Decrypt(p.EncryptedHeaderProtectionKey)
	if err != nil {
		return fmt.Errorf("decrypt AWG3 header protection key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return fmt.Errorf("decode AWG3 header protection key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("AWG3 header protection key must be 32 bytes, got %d", len(key))
	}
	p.HeaderProtectionKey = key
	p.EncryptedHeaderProtectionKey = ""
	return nil
}
