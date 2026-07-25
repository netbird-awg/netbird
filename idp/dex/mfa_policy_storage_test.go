package dex

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util/crypt"
)

func newTestMFAStorage(t *testing.T, encryptionKey string) (*mfaAwareStorage, storage.Storage) {
	t.Helper()
	base := memory.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { require.NoError(t, base.Close()) })
	wrapped, err := newMFAAwareStorage(base, encryptionKey)
	require.NoError(t, err)
	return wrapped, base
}

func TestMFAAwareStorageAppliesPerUserClientChain(t *testing.T) {
	wrapped, base := newTestMFAStorage(t, "")
	require.NoError(t, base.CreateClient(context.Background(), storage.Client{
		ID:       "netbird-dashboard",
		MFAChain: []string{"persisted-chain"},
	}))

	t.Run("administrative reads keep persisted chain", func(t *testing.T) {
		client, err := wrapped.GetClient(context.Background(), "netbird-dashboard")
		require.NoError(t, err)
		assert.Equal(t, []string{"persisted-chain"}, client.MFAChain)
	})

	wrapped.setRequirementResolver(func(_ context.Context, userID, connectorID string) (MFARequirement, error) {
		if userID == "required-user" && connectorID == "ldap-main" {
			return MFARequirementRequire, nil
		}
		return MFARequirementDisable, nil
	})

	t.Run("required user gets native TOTP", func(t *testing.T) {
		ctx := withMFARequestState(context.Background())
		rememberMFAIdentity(ctx, "required-user", "ldap-main")
		client, err := wrapped.GetClient(ctx, "netbird-dashboard")
		require.NoError(t, err)
		assert.Equal(t, []string{"persisted-chain"}, client.MFAChain)
	})

	require.NoError(t, base.UpdateClient(context.Background(), "netbird-dashboard", func(client storage.Client) (storage.Client, error) {
		client.MFAChain = nil
		return client, nil
	}))

	t.Run("required user gets default chain when account default is off", func(t *testing.T) {
		ctx := withMFARequestState(context.Background())
		rememberMFAIdentity(ctx, "required-user", "ldap-main")
		client, err := wrapped.GetClient(ctx, "netbird-dashboard")
		require.NoError(t, err)
		assert.Equal(t, []string{defaultTOTPAuthenticatorID}, client.MFAChain)
	})

	t.Run("disabled user overrides persisted account chain", func(t *testing.T) {
		require.NoError(t, base.UpdateClient(context.Background(), "netbird-dashboard", func(client storage.Client) (storage.Client, error) {
			client.MFAChain = []string{defaultTOTPAuthenticatorID}
			return client, nil
		}))
		ctx := withMFARequestState(context.Background())
		rememberMFAIdentity(ctx, "disabled-user", "local")
		client, err := wrapped.GetClient(ctx, "netbird-dashboard")
		require.NoError(t, err)
		assert.Empty(t, client.MFAChain)
	})

	t.Run("pre-authentication client lookup fails closed without returning an error", func(t *testing.T) {
		client, err := wrapped.GetClient(withMFARequestState(context.Background()), "netbird-dashboard")
		require.NoError(t, err)
		assert.Equal(t, []string{defaultTOTPAuthenticatorID}, client.MFAChain)
	})

	t.Run("unprovisioned user preserves persisted connector default", func(t *testing.T) {
		wrapped.setRequirementResolver(func(context.Context, string, string) (MFARequirement, error) {
			return MFARequirementPreserve, nil
		})
		ctx := withMFARequestState(context.Background())
		rememberMFAIdentity(ctx, "first-login-user", "ldap-main")
		client, err := wrapped.GetClient(ctx, "netbird-dashboard")
		require.NoError(t, err)
		assert.Equal(t, []string{defaultTOTPAuthenticatorID}, client.MFAChain)
	})
}

func TestMFAAwareStorageEncryptsNativeTOTPSecretAtRest(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	wrapped, base := newTestMFAStorage(t, encryptionKey)

	plainSecret := "otpauth://totp/NetBird:user@example.com?secret=JBSWY3DPEHPK3PXP"
	identity := storage.UserIdentity{
		UserID:      "user-1",
		ConnectorID: "local",
		MFASecrets: map[string]*storage.MFASecret{
			defaultTOTPAuthenticatorID: {
				AuthenticatorID: defaultTOTPAuthenticatorID,
				Type:            "TOTP",
				Secret:          plainSecret,
				CreatedAt:       time.Now().UTC(),
			},
		},
	}
	require.NoError(t, wrapped.CreateUserIdentity(context.Background(), identity))

	persisted, err := base.GetUserIdentity(context.Background(), "user-1", "local")
	require.NoError(t, err)
	persistedSecret := persisted.MFASecrets[defaultTOTPAuthenticatorID].Secret
	assert.True(t, strings.HasPrefix(persistedSecret, encryptedMFASecretPrefix))
	assert.NotContains(t, persistedSecret, plainSecret)

	decrypted, err := wrapped.GetUserIdentity(context.Background(), "user-1", "local")
	require.NoError(t, err)
	assert.Equal(t, plainSecret, decrypted.MFASecrets[defaultTOTPAuthenticatorID].Secret)

	require.NoError(t, wrapped.UpdateUserIdentity(context.Background(), "user-1", "local", func(identity storage.UserIdentity) (storage.UserIdentity, error) {
		identity.MFASecrets[defaultTOTPAuthenticatorID].Confirmed = true
		return identity, nil
	}))

	persisted, err = base.GetUserIdentity(context.Background(), "user-1", "local")
	require.NoError(t, err)
	assert.True(t, persisted.MFASecrets[defaultTOTPAuthenticatorID].Confirmed)
	assert.True(t, strings.HasPrefix(persisted.MFASecrets[defaultTOTPAuthenticatorID].Secret, encryptedMFASecretPrefix))
}

func TestMFAAwareStorageEncryptsConnectorConfigAtRest(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	wrapped, base := newTestMFAStorage(t, encryptionKey)

	plainConfig := []byte(`{"bindDN":"cn=admin,dc=example,dc=org","bindPW":"directory-secret","netbirdAccountID":"account-1"}`)
	require.NoError(t, wrapped.CreateConnector(context.Background(), storage.Connector{
		ID:     "openldap",
		Type:   "ldap",
		Config: plainConfig,
	}))

	persisted, err := base.GetConnector(context.Background(), "openldap")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(persisted.Config), encryptedConnectorPrefix))
	assert.NotContains(t, string(persisted.Config), "directory-secret")

	decrypted, err := wrapped.GetConnector(context.Background(), "openldap")
	require.NoError(t, err)
	assert.JSONEq(t, string(plainConfig), string(decrypted.Config))

	require.NoError(t, wrapped.UpdateConnector(context.Background(), "openldap", func(connector storage.Connector) (storage.Connector, error) {
		connector.Name = "LDAP"
		return connector, nil
	}))
	persisted, err = base.GetConnector(context.Background(), "openldap")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(persisted.Config), encryptedConnectorPrefix))
}

func TestMFAAwareStorageMigratesPlaintextConnectorConfig(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	wrapped, base := newTestMFAStorage(t, encryptionKey)
	require.NoError(t, base.CreateConnector(context.Background(), storage.Connector{
		ID: "legacy", Type: "oidc", Config: []byte(`{"clientSecret":"legacy-secret"}`),
	}))

	require.NoError(t, wrapped.encryptConnectorConfigsAtRest(context.Background()))
	persisted, err := base.GetConnector(context.Background(), "legacy")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(persisted.Config), encryptedConnectorPrefix))
	assert.NotContains(t, string(persisted.Config), "legacy-secret")

	decrypted, err := wrapped.GetConnector(context.Background(), "legacy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"clientSecret":"legacy-secret"}`, string(decrypted.Config))
}
