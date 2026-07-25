package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyEnvironmentOverridesSecrets(t *testing.T) {
	t.Setenv("NB_SERVER_AUTH_SECRET", "relay-secret")
	t.Setenv("NB_AUTH_OWNER_PASSWORD", "owner-secret")
	t.Setenv("NB_AUTH_LDAP_BIND_PASSWORD", "ldap-secret")
	t.Setenv("NB_STORE_POSTGRES_DSN", "postgres-dsn")
	t.Setenv("NB_DATASTORE_ENCRYPTION_KEY", "encryption-key")

	cfg := DefaultConfig()
	cfg.Server.Auth.Owner = &AuthOwnerConfig{}
	cfg.Server.Auth.Connectors = []AuthConnectorConfig{{
		Type:   "ldap",
		Config: map[string]interface{}{"bindPW": ""},
	}}

	applyEnvironmentOverrides(cfg)

	require.Equal(t, "relay-secret", cfg.Server.AuthSecret)
	require.Equal(t, "owner-secret", cfg.Server.Auth.Owner.Password)
	require.Equal(t, "ldap-secret", cfg.Server.Auth.Connectors[0].Config["bindPW"])
	require.Equal(t, "postgres-dsn", cfg.Server.Store.DSN)
	require.Equal(t, "postgres-dsn", cfg.Server.ActivityStore.DSN)
	require.Equal(t, "postgres-dsn", cfg.Server.AuthStore.DSN)
	require.Equal(t, "encryption-key", cfg.Server.Store.EncryptionKey)
}
