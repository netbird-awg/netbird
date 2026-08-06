package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

func TestEnsureEncryptionKeyPersistsGeneratedKey(t *testing.T) {
	dataDir := t.TempDir()
	first := &nbconfig.Config{Datadir: dataDir}

	require.NoError(t, EnsureEncryptionKey(context.Background(), first))
	require.NotEmpty(t, first.DataStoreEncryptionKey)

	keyPath := filepath.Join(dataDir, datastoreEncryptionKeyFilename)
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	second := &nbconfig.Config{Datadir: dataDir}
	require.NoError(t, EnsureEncryptionKey(context.Background(), second))
	assert.Equal(t, first.DataStoreEncryptionKey, second.DataStoreEncryptionKey)
}

func TestEnsureEncryptionKeyKeepsExplicitConfig(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &nbconfig.Config{
		Datadir:                dataDir,
		DataStoreEncryptionKey: "explicit-key",
	}

	require.NoError(t, EnsureEncryptionKey(context.Background(), cfg))
	assert.Equal(t, "explicit-key", cfg.DataStoreEncryptionKey)
	_, err := os.Stat(filepath.Join(dataDir, datastoreEncryptionKeyFilename))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestEnsureEncryptionKeyRejectsInvalidPersistedKey(t *testing.T) {
	dataDir := t.TempDir()
	keyPath := filepath.Join(dataDir, datastoreEncryptionKeyFilename)
	require.NoError(t, os.WriteFile(keyPath, []byte("invalid"), 0o600))

	err := EnsureEncryptionKey(context.Background(), &nbconfig.Config{Datadir: dataDir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid datastore encryption key file")
}
