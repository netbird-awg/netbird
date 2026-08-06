package dex

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/storage"
	"golang.org/x/crypto/bcrypt"
)

// SupportsUserPasswordManagement reports whether the embedded identity
// provider owns the password lifecycle for the user. External OIDC/SAML
// connector passwords must be managed by their upstream identity provider.
func (p *Provider) SupportsUserPasswordManagement(ctx context.Context, userID string) (bool, error) {
	_, connectorID := decodeConnectorUserID(userID)
	if connectorID == "" || connectorID == LocalConnectorID {
		return true, nil
	}
	conn, err := p.GetConnector(ctx, connectorID)
	if err != nil {
		return false, fmt.Errorf("failed to get connector %s: %w", connectorID, err)
	}
	return conn.Type == "ldap" && conn.LDAP != nil, nil
}

func (p *Provider) updateUserPassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	rawUID, connectorID := decodeConnectorUserID(userID)
	if connectorID != "" && connectorID != LocalConnectorID {
		conn, err := p.GetConnector(ctx, connectorID)
		if err != nil {
			return fmt.Errorf("failed to get connector %s: %w", connectorID, err)
		}
		if conn.Type == "ldap" && conn.LDAP != nil {
			return UpdateLDAPUserPassword(conn.LDAP, rawUID, oldPassword, newPassword)
		}
		return fmt.Errorf("password change is not supported for connector type %q", conn.Type)
	}

	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword(user.Hash, []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}
	return p.replaceLocalPassword(ctx, user, newPassword, "update")
}

// ResetUserPassword resets a user's password without requiring the old password.
func (p *Provider) ResetUserPassword(ctx context.Context, userID, newPassword string) error {
	rawUID, connectorID := decodeConnectorUserID(userID)
	if connectorID != "" && connectorID != LocalConnectorID {
		conn, err := p.GetConnector(ctx, connectorID)
		if err != nil {
			return fmt.Errorf("failed to get connector %s: %w", connectorID, err)
		}
		if conn.Type == "ldap" && conn.LDAP != nil {
			return ResetLDAPUserPassword(conn.LDAP, rawUID, newPassword)
		}
		return fmt.Errorf("password reset is not supported for connector type %q", conn.Type)
	}

	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	return p.replaceLocalPassword(ctx, user, newPassword, "reset")
}

func decodeConnectorUserID(userID string) (string, string) {
	rawUID, connectorID, err := DecodeDexUserID(userID)
	if err != nil {
		return userID, ""
	}
	return rawUID, connectorID
}

func (p *Provider) replaceLocalPassword(ctx context.Context, user storage.Password, newPassword, operation string) error {
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}
	if err := p.storage.UpdatePassword(ctx, user.Email, func(old storage.Password) (storage.Password, error) {
		old.Hash = newHash
		return old, nil
	}); err != nil {
		return fmt.Errorf("failed to %s password: %w", operation, err)
	}
	return nil
}
