package dex

import (
	"context"
	"testing"

	"github.com/dexidp/dex/storage"
	"github.com/stretchr/testify/require"
)

func TestSupportsUserPasswordManagement(t *testing.T) {
	ctx := context.Background()
	provider, cleanup := newTestProvider(t)
	defer cleanup()

	require.NoError(t, provider.storage.CreateConnector(ctx, storage.Connector{
		ID: "ldap-a", Type: "ldap", Name: "LDAP", Config: []byte(`{}`),
	}))
	require.NoError(t, provider.storage.CreateConnector(ctx, storage.Connector{
		ID: "oidc-a", Type: "oidc", Name: "OIDC", Config: []byte(`{}`),
	}))

	tests := []struct {
		name      string
		userID    string
		supported bool
	}{
		{name: "local", userID: EncodeDexUserID("local-user", "local"), supported: true},
		{name: "ldap", userID: EncodeDexUserID("ldap-user", "ldap-a"), supported: true},
		{name: "external oidc", userID: EncodeDexUserID("oidc-user", "oidc-a"), supported: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supported, err := provider.SupportsUserPasswordManagement(ctx, test.userID)
			require.NoError(t, err)
			require.Equal(t, test.supported, supported)
		})
	}
}
