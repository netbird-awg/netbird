package dex

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dexidp/dex/storage"

	"github.com/netbirdio/netbird/util/crypt"
)

const (
	defaultTOTPAuthenticatorID = "default-totp"
	encryptedMFASecretPrefix   = "enc:v1:"
	encryptedConnectorPrefix   = "enc:v1:"
)

// MFARequirementResolver decides whether a specific user must complete the
// native Dex MFA chain. The user ID is the raw connector user ID, not the
// NetBird-encoded subject.
type MFARequirementResolver func(ctx context.Context, userID, connectorID string) (bool, error)

// MFAAttemptLimiter persists native TOTP failure state outside Dex. Returning a
// positive retry duration blocks the request with HTTP 429.
type MFAAttemptLimiter interface {
	Check(ctx context.Context, userID, connectorID string) (time.Duration, error)
	RecordFailure(ctx context.Context, userID, connectorID string) error
	Clear(ctx context.Context, userID, connectorID string) error
}

type mfaRequestStateKey struct{}

type mfaRequestState struct {
	mu          sync.RWMutex
	userID      string
	connectorID string
}

func withMFARequestState(ctx context.Context) context.Context {
	return context.WithValue(ctx, mfaRequestStateKey{}, &mfaRequestState{})
}

func requestMFAState(ctx context.Context) (*mfaRequestState, bool) {
	state, ok := ctx.Value(mfaRequestStateKey{}).(*mfaRequestState)
	return state, ok
}

func rememberMFAIdentity(ctx context.Context, userID, connectorID string) {
	if userID == "" || connectorID == "" {
		return
	}
	state, ok := requestMFAState(ctx)
	if !ok {
		return
	}
	state.mu.Lock()
	state.userID = userID
	state.connectorID = connectorID
	state.mu.Unlock()
}

func currentMFAIdentity(ctx context.Context) (userID, connectorID string, attached bool) {
	state, ok := requestMFAState(ctx)
	if !ok {
		return "", "", false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.userID, state.connectorID, true
}

// mfaAwareStorage decorates Dex storage without changing the upstream Dex
// module. It applies a per-request MFA chain and encrypts TOTP and connector
// configuration secrets at rest.
// All unmodified Storage methods are delegated through the embedded interface.
type mfaAwareStorage struct {
	storage.Storage

	mu        sync.RWMutex
	resolver  MFARequirementResolver
	encryptor *crypt.FieldEncrypt
}

func newMFAAwareStorage(base storage.Storage, encryptionKey string) (*mfaAwareStorage, error) {
	wrapped := &mfaAwareStorage{Storage: base}
	if strings.TrimSpace(encryptionKey) == "" {
		return wrapped, nil
	}

	encryptor, err := crypt.NewFieldEncrypt(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create MFA secret encryptor: %w", err)
	}
	wrapped.encryptor = encryptor
	return wrapped, nil
}

func (s *mfaAwareStorage) setRequirementResolver(resolver MFARequirementResolver) {
	s.mu.Lock()
	s.resolver = resolver
	s.mu.Unlock()
}

func (s *mfaAwareStorage) requirementResolver() MFARequirementResolver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolver
}

func (s *mfaAwareStorage) CreateConnector(ctx context.Context, connector storage.Connector) error {
	encrypted, err := s.encryptConnector(connector)
	if err != nil {
		return err
	}
	return s.Storage.CreateConnector(ctx, encrypted)
}

func (s *mfaAwareStorage) GetConnector(ctx context.Context, id string) (storage.Connector, error) {
	connector, err := s.Storage.GetConnector(ctx, id)
	if err != nil {
		return storage.Connector{}, err
	}
	return s.decryptConnector(connector)
}

func (s *mfaAwareStorage) ListConnectors(ctx context.Context) ([]storage.Connector, error) {
	connectors, err := s.Storage.ListConnectors(ctx)
	if err != nil {
		return nil, err
	}
	for i := range connectors {
		connectors[i], err = s.decryptConnector(connectors[i])
		if err != nil {
			return nil, err
		}
	}
	return connectors, nil
}

func (s *mfaAwareStorage) UpdateConnector(ctx context.Context, id string, updater func(storage.Connector) (storage.Connector, error)) error {
	return s.Storage.UpdateConnector(ctx, id, func(connector storage.Connector) (storage.Connector, error) {
		decrypted, err := s.decryptConnector(connector)
		if err != nil {
			return storage.Connector{}, err
		}
		updated, err := updater(decrypted)
		if err != nil {
			return storage.Connector{}, err
		}
		return s.encryptConnector(updated)
	})
}

func (s *mfaAwareStorage) encryptConnectorConfigsAtRest(ctx context.Context) error {
	if s.encryptor == nil {
		return nil
	}
	connectors, err := s.Storage.ListConnectors(ctx)
	if err != nil {
		return err
	}
	for _, connector := range connectors {
		if len(connector.Config) == 0 || strings.HasPrefix(string(connector.Config), encryptedConnectorPrefix) {
			continue
		}
		if err := s.UpdateConnector(ctx, connector.ID, func(current storage.Connector) (storage.Connector, error) {
			return current, nil
		}); err != nil {
			return fmt.Errorf("migrate connector config %s to encrypted storage: %w", connector.ID, err)
		}
	}
	return nil
}

func (s *mfaAwareStorage) encryptConnector(connector storage.Connector) (storage.Connector, error) {
	connector.Config = append([]byte(nil), connector.Config...)
	if s.encryptor == nil || len(connector.Config) == 0 || strings.HasPrefix(string(connector.Config), encryptedConnectorPrefix) {
		return connector, nil
	}
	ciphertext, err := s.encryptor.Encrypt(string(connector.Config))
	if err != nil {
		return storage.Connector{}, fmt.Errorf("encrypt connector config %s: %w", connector.ID, err)
	}
	connector.Config = []byte(encryptedConnectorPrefix + ciphertext)
	return connector, nil
}

func (s *mfaAwareStorage) decryptConnector(connector storage.Connector) (storage.Connector, error) {
	connector.Config = append([]byte(nil), connector.Config...)
	if s.encryptor == nil || !strings.HasPrefix(string(connector.Config), encryptedConnectorPrefix) {
		return connector, nil
	}
	plaintext, err := s.encryptor.Decrypt(strings.TrimPrefix(string(connector.Config), encryptedConnectorPrefix))
	if err != nil {
		return storage.Connector{}, fmt.Errorf("decrypt connector config %s: %w", connector.ID, err)
	}
	connector.Config = []byte(plaintext)
	return connector, nil
}

func (s *mfaAwareStorage) GetClient(ctx context.Context, id string) (storage.Client, error) {
	client, err := s.Storage.GetClient(ctx, id)
	if err != nil {
		return storage.Client{}, err
	}

	resolver := s.requirementResolver()
	if resolver == nil {
		return client, nil
	}

	userID, connectorID, attached := currentMFAIdentity(ctx)
	if !attached {
		// Administrative storage operations don't have an HTTP request state and
		// must see the persisted client unchanged.
		return client, nil
	}
	if userID == "" || connectorID == "" {
		// Dex validates the OAuth client before authenticating the user. At that
		// point there is no identity whose per-user policy can be resolved yet.
		// Keep the request alive while failing closed with native TOTP if a later
		// MFA decision is reached without the identity-aware storage calls below.
		if len(client.MFAChain) == 0 {
			client.MFAChain = []string{defaultTOTPAuthenticatorID}
		}
		return client, nil
	}

	required, err := resolver(ctx, userID, connectorID)
	if err != nil {
		return storage.Client{}, fmt.Errorf("resolve MFA policy for user %s via connector %s: %w", userID, connectorID, err)
	}
	if !required {
		client.MFAChain = []string{}
		return client, nil
	}
	if len(client.MFAChain) == 0 {
		client.MFAChain = []string{defaultTOTPAuthenticatorID}
	}
	return client, nil
}

func (s *mfaAwareStorage) CreateAuthRequest(ctx context.Context, request storage.AuthRequest) error {
	rememberMFAIdentity(ctx, request.Claims.UserID, request.ConnectorID)
	return s.Storage.CreateAuthRequest(ctx, request)
}

func (s *mfaAwareStorage) GetAuthRequest(ctx context.Context, id string) (storage.AuthRequest, error) {
	request, err := s.Storage.GetAuthRequest(ctx, id)
	if err == nil {
		rememberMFAIdentity(ctx, request.Claims.UserID, request.ConnectorID)
	}
	return request, err
}

func (s *mfaAwareStorage) UpdateAuthRequest(ctx context.Context, id string, updater func(storage.AuthRequest) (storage.AuthRequest, error)) error {
	return s.Storage.UpdateAuthRequest(ctx, id, func(request storage.AuthRequest) (storage.AuthRequest, error) {
		rememberMFAIdentity(ctx, request.Claims.UserID, request.ConnectorID)
		updated, err := updater(request)
		if err == nil {
			rememberMFAIdentity(ctx, updated.Claims.UserID, updated.ConnectorID)
		}
		return updated, err
	})
}

func (s *mfaAwareStorage) CreatePassword(ctx context.Context, password storage.Password) error {
	rememberMFAIdentity(ctx, password.UserID, LocalConnectorID)
	return s.Storage.CreatePassword(ctx, password)
}

func (s *mfaAwareStorage) GetPassword(ctx context.Context, email string) (storage.Password, error) {
	password, err := s.Storage.GetPassword(ctx, email)
	if err == nil {
		rememberMFAIdentity(ctx, password.UserID, LocalConnectorID)
	}
	return password, err
}

func (s *mfaAwareStorage) CreateAuthSession(ctx context.Context, session storage.AuthSession) error {
	rememberMFAIdentity(ctx, session.UserID, session.ConnectorID)
	return s.Storage.CreateAuthSession(ctx, session)
}

func (s *mfaAwareStorage) GetAuthSession(ctx context.Context, userID, connectorID string) (storage.AuthSession, error) {
	rememberMFAIdentity(ctx, userID, connectorID)
	return s.Storage.GetAuthSession(ctx, userID, connectorID)
}

func (s *mfaAwareStorage) UpdateAuthSession(ctx context.Context, userID, connectorID string, updater func(storage.AuthSession) (storage.AuthSession, error)) error {
	rememberMFAIdentity(ctx, userID, connectorID)
	return s.Storage.UpdateAuthSession(ctx, userID, connectorID, updater)
}

func (s *mfaAwareStorage) CreateUserIdentity(ctx context.Context, identity storage.UserIdentity) error {
	rememberMFAIdentity(ctx, identity.UserID, identity.ConnectorID)
	encrypted, err := s.encryptUserIdentity(identity)
	if err != nil {
		return err
	}
	return s.Storage.CreateUserIdentity(ctx, encrypted)
}

func (s *mfaAwareStorage) GetUserIdentity(ctx context.Context, userID, connectorID string) (storage.UserIdentity, error) {
	rememberMFAIdentity(ctx, userID, connectorID)
	identity, err := s.Storage.GetUserIdentity(ctx, userID, connectorID)
	if err != nil {
		return storage.UserIdentity{}, err
	}
	return s.decryptUserIdentity(identity)
}

func (s *mfaAwareStorage) ListUserIdentities(ctx context.Context) ([]storage.UserIdentity, error) {
	identities, err := s.Storage.ListUserIdentities(ctx)
	if err != nil {
		return nil, err
	}
	for index := range identities {
		identities[index], err = s.decryptUserIdentity(identities[index])
		if err != nil {
			return nil, err
		}
	}
	return identities, nil
}

func (s *mfaAwareStorage) UpdateUserIdentity(ctx context.Context, userID, connectorID string, updater func(storage.UserIdentity) (storage.UserIdentity, error)) error {
	rememberMFAIdentity(ctx, userID, connectorID)
	return s.Storage.UpdateUserIdentity(ctx, userID, connectorID, func(identity storage.UserIdentity) (storage.UserIdentity, error) {
		decrypted, err := s.decryptUserIdentity(identity)
		if err != nil {
			return storage.UserIdentity{}, err
		}
		updated, err := updater(decrypted)
		if err != nil {
			return storage.UserIdentity{}, err
		}
		return s.encryptUserIdentity(updated)
	})
}

func (s *mfaAwareStorage) encryptUserIdentity(identity storage.UserIdentity) (storage.UserIdentity, error) {
	identity = cloneUserIdentityMFASecrets(identity)
	if s.encryptor == nil {
		return identity, nil
	}
	for authenticatorID, secret := range identity.MFASecrets {
		if secret == nil || secret.Secret == "" || strings.HasPrefix(secret.Secret, encryptedMFASecretPrefix) {
			continue
		}
		ciphertext, err := s.encryptor.Encrypt(secret.Secret)
		if err != nil {
			return storage.UserIdentity{}, fmt.Errorf("encrypt MFA secret %s for user %s: %w", authenticatorID, identity.UserID, err)
		}
		secret.Secret = encryptedMFASecretPrefix + ciphertext
	}
	return identity, nil
}

func (s *mfaAwareStorage) decryptUserIdentity(identity storage.UserIdentity) (storage.UserIdentity, error) {
	identity = cloneUserIdentityMFASecrets(identity)
	if s.encryptor == nil {
		return identity, nil
	}
	for authenticatorID, secret := range identity.MFASecrets {
		if secret == nil || !strings.HasPrefix(secret.Secret, encryptedMFASecretPrefix) {
			continue
		}
		plaintext, err := s.encryptor.Decrypt(strings.TrimPrefix(secret.Secret, encryptedMFASecretPrefix))
		if err != nil {
			return storage.UserIdentity{}, fmt.Errorf("decrypt MFA secret %s for user %s: %w", authenticatorID, identity.UserID, err)
		}
		secret.Secret = plaintext
	}
	return identity, nil
}

func cloneUserIdentityMFASecrets(identity storage.UserIdentity) storage.UserIdentity {
	if identity.MFASecrets == nil {
		return identity
	}
	cloned := make(map[string]*storage.MFASecret, len(identity.MFASecrets))
	for authenticatorID, secret := range identity.MFASecrets {
		if secret == nil {
			cloned[authenticatorID] = nil
			continue
		}
		secretCopy := *secret
		cloned[authenticatorID] = &secretCopy
	}
	identity.MFASecrets = cloned
	return identity
}
