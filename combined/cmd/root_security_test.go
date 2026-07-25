package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskSecretFullyRedacts(t *testing.T) {
	const secret = "sensitive-value"
	masked := maskSecret(secret)
	require.Equal(t, "****", masked)
	require.NotContains(t, masked, secret[:4])
}

func TestMaskDSNPassword(t *testing.T) {
	for name, dsn := range map[string]string{
		"key value": "host=db user=netbird password=sensitive dbname=netbird",
		"URI":       "postgres://netbird:sensitive@db:5432/netbird",
	} {
		t.Run(name, func(t *testing.T) {
			masked := maskDSNPassword(dsn)
			require.NotContains(t, masked, "sensitive")
			require.True(t, strings.Contains(masked, "****"))
		})
	}
}
