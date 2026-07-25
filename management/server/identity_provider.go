package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dexidp/dex/storage"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/outbound"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// oidcProviderJSON represents the OpenID Connect discovery document
type oidcProviderJSON struct {
	Issuer string `json:"issuer"`
}

// validateOIDCIssuer validates the OIDC issuer by fetching the OpenID configuration
// and verifying that the returned issuer matches the configured one.
func validateOIDCIssuer(ctx context.Context, issuer string) error {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	validator, err := outbound.NewValidatorFromEnv()
	if err != nil {
		return fmt.Errorf("%w: invalid outbound allowlist: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}
	target, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}
	if _, err := validator.ValidateURL(ctx, target.URL); err != nil {
		return fmt.Errorf("%w: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}
	return validateOIDCIssuerWithHTTPClient(ctx, issuer, validator.HTTPClient())
}

// validateOIDCIssuerWithHTTPClient performs discovery-document validation with
// a caller-provided client. Production callers must use validateOIDCIssuer so
// outbound destination validation and DNS pinning cannot be bypassed.
func validateOIDCIssuerWithHTTPClient(ctx context.Context, issuer string, httpClient *http.Client) error {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	target, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}

	resp, err := httpClient.Do(target)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}
	defer resp.Body.Close()

	const maxOIDCDiscoveryBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCDiscoveryBytes+1))
	if err != nil {
		return fmt.Errorf("%w: unable to read response body: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}
	if len(body) > maxOIDCDiscoveryBytes {
		return fmt.Errorf("%w: discovery response exceeds %d bytes", types.ErrIdentityProviderIssuerUnreachable, maxOIDCDiscoveryBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: discovery endpoint returned %s", types.ErrIdentityProviderIssuerUnreachable, resp.Status)
	}

	var p oidcProviderJSON
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("%w: failed to decode provider discovery object: %v", types.ErrIdentityProviderIssuerUnreachable, err)
	}

	if p.Issuer != issuer {
		return fmt.Errorf("%w: expected %q got %q", types.ErrIdentityProviderIssuerMismatch, issuer, p.Issuer)
	}

	return nil
}

// validateIdentityProviderConfig validates the identity provider configuration including
// basic validation and OIDC issuer verification.
func validateIdentityProviderConfig(ctx context.Context, idpConfig *types.IdentityProvider) error {
	if err := idpConfig.Validate(); err != nil {
		return status.Errorf(status.InvalidArgument, "%s", err.Error())
	}

	// LDAP connectors don't use OIDC discovery
	if idpConfig.Type == types.IdentityProviderTypeLDAP {
		return nil
	}

	// Validate the issuer by calling the OIDC discovery endpoint
	if idpConfig.Issuer != "" {
		if err := validateOIDCIssuer(ctx, idpConfig.Issuer); err != nil {
			return status.Errorf(status.InvalidArgument, "%s", err.Error())
		}
	}

	return nil
}

// GetIdentityProviders returns all identity providers for an account
func (am *DefaultAccountManager) GetIdentityProviders(ctx context.Context, accountID, userID string) ([]*types.IdentityProvider, error) {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		log.Warn("identity provider management requires embedded IdP")
		return []*types.IdentityProvider{}, nil
	}

	connectors, err := embeddedManager.ListConnectors(ctx)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to list identity providers: %v", err)
	}

	result := make([]*types.IdentityProvider, 0, len(connectors))
	for _, conn := range connectors {
		visible, err := am.ensureIdentityProviderAccount(ctx, embeddedManager, accountID, conn)
		if err != nil {
			return nil, err
		}
		if !visible {
			continue
		}
		result = append(result, connectorConfigToIdentityProvider(conn, accountID))
	}

	return result, nil
}

// GetIdentityProvider returns a specific identity provider by ID
func (am *DefaultAccountManager) GetIdentityProvider(ctx context.Context, accountID, idpID, userID string) (*types.IdentityProvider, error) {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	conn, err := am.getIdentityProviderConnector(ctx, embeddedManager, accountID, idpID)
	if err != nil {
		return nil, err
	}

	return connectorConfigToIdentityProvider(conn, accountID), nil
}

// CreateIdentityProvider creates a new identity provider
func (am *DefaultAccountManager) CreateIdentityProvider(ctx context.Context, accountID, userID string, idpConfig *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProviderConfig(ctx, idpConfig); err != nil {
		return nil, err
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	// Generate ID if not provided
	if idpConfig.ID == "" {
		idpConfig.ID = generateIdentityProviderID(idpConfig.Type)
	}
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	_, err = embeddedManager.CreateConnector(ctx, connCfg)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to create identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpConfig.ID, accountID, activity.IdentityProviderCreated, idpConfig.EventMeta())

	return idpConfig, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (am *DefaultAccountManager) UpdateIdentityProvider(ctx context.Context, accountID, idpID, userID string, idpConfig *types.IdentityProvider) (*types.IdentityProvider, error) {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err := validateIdentityProviderConfig(ctx, idpConfig); err != nil {
		return nil, err
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}
	if _, err := am.getIdentityProviderConnector(ctx, embeddedManager, accountID, idpID); err != nil {
		return nil, err
	}

	idpConfig.ID = idpID
	idpConfig.AccountID = accountID

	connCfg := identityProviderToConnectorConfig(idpConfig)

	if err := embeddedManager.UpdateConnector(ctx, connCfg); err != nil {
		return nil, status.Errorf(status.Internal, "failed to update identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpConfig.ID, accountID, activity.IdentityProviderUpdated, idpConfig.EventMeta())

	return idpConfig, nil
}

// DeleteIdentityProvider deletes an identity provider
func (am *DefaultAccountManager) DeleteIdentityProvider(ctx context.Context, accountID, idpID, userID string) error {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	// Get the IDP info before deleting for the activity event
	conn, err := am.getIdentityProviderConnector(ctx, embeddedManager, accountID, idpID)
	if err != nil {
		return err
	}
	idpConfig := connectorConfigToIdentityProvider(conn, accountID)
	if err := am.ensureIdentityProviderNotReferenced(ctx, accountID, idpID); err != nil {
		return err
	}

	if err := embeddedManager.DeleteConnector(ctx, idpID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return status.Errorf(status.NotFound, "identity provider not found")
		}
		return status.Errorf(status.Internal, "failed to delete identity provider: %v", err)
	}

	am.StoreEvent(ctx, userID, idpID, accountID, activity.IdentityProviderDeleted, idpConfig.EventMeta())

	return nil
}

type ldapSyncConfigReferenceChecker interface {
	HasLDAPSyncConfig(ctx context.Context, accountID, connectorID string) (bool, error)
}

func (am *DefaultAccountManager) ensureIdentityProviderNotReferenced(ctx context.Context, accountID, idpID string) error {
	users, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to check identity provider references")
	}
	for _, user := range users {
		_, connectorID, decodeErr := dex.DecodeDexUserID(user.Id)
		if decodeErr == nil && connectorID == idpID {
			return status.Errorf(status.PreconditionFailed, "identity provider is still referenced by user %s", user.Id)
		}
	}

	invites, err := am.Store.GetAccountUserInvites(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return status.Errorf(status.Internal, "failed to check identity provider invitations")
	}
	for _, invite := range invites {
		if invite.IdpID == idpID {
			return status.Errorf(status.PreconditionFailed, "identity provider is still referenced by a pending user")
		}
	}

	if checker, ok := am.Store.(ldapSyncConfigReferenceChecker); ok {
		referenced, err := checker.HasLDAPSyncConfig(ctx, accountID, idpID)
		if err != nil {
			return status.Errorf(status.Internal, "failed to check LDAP synchronization references")
		}
		if referenced {
			return status.Errorf(status.PreconditionFailed, "identity provider is still referenced by local LDAP synchronization")
		}
	}
	return nil
}

// connectorConfigToIdentityProvider converts a dex.ConnectorConfig to types.IdentityProvider
func connectorConfigToIdentityProvider(conn *dex.ConnectorConfig, accountID string) *types.IdentityProvider {
	identityProvider := &types.IdentityProvider{
		ID:           conn.ID,
		AccountID:    accountID,
		Type:         types.IdentityProviderType(conn.Type),
		Name:         conn.Name,
		Issuer:       conn.Issuer,
		ClientID:     conn.ClientID,
		ClientSecret: conn.ClientSecret,
	}
	applyLDAPConnectorConfig(identityProvider, conn.LDAP)
	return identityProvider
}

// identityProviderToConnectorConfig converts a types.IdentityProvider to dex.ConnectorConfig
func identityProviderToConnectorConfig(idpConfig *types.IdentityProvider) *dex.ConnectorConfig {
	cfg := &dex.ConnectorConfig{
		ID:           idpConfig.ID,
		Name:         idpConfig.Name,
		Type:         string(idpConfig.Type),
		Issuer:       idpConfig.Issuer,
		ClientID:     idpConfig.ClientID,
		ClientSecret: idpConfig.ClientSecret,
		AccountID:    idpConfig.AccountID,
	}
	if idpConfig.Type == types.IdentityProviderTypeLDAP {
		cfg.LDAP = identityProviderLDAPConnectorConfig(idpConfig)
	}
	return cfg
}

func (am *DefaultAccountManager) getIdentityProviderConnector(ctx context.Context, embeddedManager *idp.EmbeddedIdPManager, accountID, idpID string) (*dex.ConnectorConfig, error) {
	conn, err := embeddedManager.GetConnector(ctx, idpID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, status.Errorf(status.NotFound, "identity provider not found")
		}
		return nil, status.Errorf(status.Internal, "failed to get identity provider: %v", err)
	}
	visible, err := am.ensureIdentityProviderAccount(ctx, embeddedManager, accountID, conn)
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, status.Errorf(status.NotFound, "identity provider not found")
	}
	return conn, nil
}

// ensureIdentityProviderAccount isolates embedded Dex connectors by NetBird
// account. Legacy/static connectors without ownership are claimed only when
// the installation contains exactly one account, avoiding cross-tenant leaks.
func (am *DefaultAccountManager) ensureIdentityProviderAccount(ctx context.Context, embeddedManager *idp.EmbeddedIdPManager, accountID string, conn *dex.ConnectorConfig) (bool, error) {
	if conn.AccountID != "" {
		return conn.AccountID == accountID, nil
	}
	accounts := am.Store.GetAllAccounts(ctx)
	if len(accounts) != 1 || accounts[0].Id != accountID {
		return false, nil
	}
	conn.AccountID = accountID
	if err := embeddedManager.UpdateConnector(ctx, conn); err != nil {
		return false, status.Errorf(status.Internal, "failed to claim legacy identity provider: %v", err)
	}
	return true, nil
}

// generateIdentityProviderID generates a unique ID for an identity provider.
// For specific provider types (okta, zitadel, entra, google, pocketid, microsoft, adfs),
// the ID is prefixed with the type name. Generic OIDC providers get no prefix.
func generateIdentityProviderID(idpType types.IdentityProviderType) string {
	id := xid.New().String()

	switch idpType {
	case types.IdentityProviderTypeOkta:
		return "okta-" + id
	case types.IdentityProviderTypeZitadel:
		return "zitadel-" + id
	case types.IdentityProviderTypeEntra:
		return "entra-" + id
	case types.IdentityProviderTypeGoogle:
		return "google-" + id
	case types.IdentityProviderTypePocketID:
		return "pocketid-" + id
	case types.IdentityProviderTypeMicrosoft:
		return "microsoft-" + id
	case types.IdentityProviderTypeAuthentik:
		return "authentik-" + id
	case types.IdentityProviderTypeKeycloak:
		return "keycloak-" + id
	case types.IdentityProviderTypeADFS:
		return "adfs-" + id
	case types.IdentityProviderTypeLDAP:
		return "ldap-" + id
	default:
		// Generic OIDC - no prefix
		return id
	}
}
