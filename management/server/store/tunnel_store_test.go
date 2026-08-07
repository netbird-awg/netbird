package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestEnsureAccountTunnelPolicyTimestamps(t *testing.T) {
	accountCreatedAt := time.Date(2026, time.August, 7, 1, 2, 3, 0, time.UTC)
	userCreatedAt := accountCreatedAt.Add(time.Minute)
	account := &types.Account{
		CreatedAt: accountCreatedAt,
		Settings:  &types.Settings{},
		Users: map[string]*types.User{
			"user": {
				CreatedAt: userCreatedAt,
			},
		},
	}

	ensureAccountTunnelPolicyTimestamps(account)

	require.Equal(t, accountCreatedAt, account.Settings.TunnelPolicyUpdatedAt)
	require.Equal(
		t,
		userCreatedAt,
		account.Users["user"].TunnelPolicyUpdatedAt,
	)
}

func TestTunnelStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	sqlStore, ok := store.(*SqlStore)
	require.True(t, ok)

	now := time.Now().UTC().Truncate(time.Millisecond)
	account := newAccountWithId(ctx, "tunnel-account", "tunnel-user", "")
	account.Settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
	account.Settings.TunnelPolicyUpdatedAt = now
	account.Settings.TunnelProfile = &types.TunnelProfile{
		ProtocolVersion: "awg2",
		Revision:        9,
		Parameters: json.RawMessage(
			`{"h1":"101","h2":"102","h3":"103","h4":"104"}`,
		),
		UpdatedAt: now,
	}
	user := account.Users["tunnel-user"]
	user.TunnelPolicy = types.TunnelUserPolicyPreferAWG
	user.TunnelPolicyUpdatedAt = now
	account.Peers["tunnel-peer"] = &nbpeer.Peer{
		ID:        "tunnel-peer",
		AccountID: account.Id,
		UserID:    user.Id,
		Key:       "tunnel-peer-key",
		IP:        netip.MustParseAddr("100.64.0.10"),
		Meta: nbpeer.PeerSystemMeta{
			TunnelRuntime: nbpeer.TunnelRuntimeMeta{
				ProtocolVersion:   "awg2",
				ProfileRevision:   9,
				AdapterRevision:   "adapter",
				Ready:             true,
				UpdatedAt:         now,
				LastReadyProtocol: "awg2",
				LastReadyRevision: 9,
				LastReadyAt:       now,
			},
		},
	}

	require.NoError(t, sqlStore.SaveAccount(ctx, account))

	stored, err := sqlStore.GetAccount(ctx, account.Id)
	require.NoError(t, err)
	require.Equal(t, account.Settings.TunnelPolicy, stored.Settings.TunnelPolicy)
	require.Equal(t, account.Settings.TunnelProfile, stored.Settings.TunnelProfile)
	require.Equal(t, user.TunnelPolicy, stored.Users[user.Id].TunnelPolicy)
	require.Equal(
		t,
		account.Peers["tunnel-peer"].Meta.TunnelRuntime,
		stored.Peers["tunnel-peer"].Meta.TunnelRuntime,
	)
}

func TestAWG3HeaderProtectionKeyIsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	store, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	sqlStore, ok := store.(*SqlStore)
	require.True(t, ok)

	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)
	sqlStore.SetFieldEncrypt(fieldEncrypt)

	headerKey := bytes.Repeat([]byte{0x6a}, 32)
	account := newAccountWithId(ctx, "awg3-account", "awg3-user", "")
	account.Settings.TunnelProfile = &types.TunnelProfile{
		ProtocolVersion:     "awg3",
		Revision:            2,
		Parameters:          json.RawMessage(`{"h1":"101"}`),
		HeaderProtectionKey: bytes.Clone(headerKey),
	}
	account.Settings.TunnelProfilePending = &types.TunnelProfile{
		ProtocolVersion:     "awg3",
		Revision:            3,
		Parameters:          json.RawMessage(`{"h1":"102"}`),
		HeaderProtectionKey: bytes.Repeat([]byte{0x7b}, 32),
	}
	account.Settings.TunnelProfilePrevious = &types.TunnelProfile{
		ProtocolVersion:     "awg3",
		Revision:            1,
		Parameters:          json.RawMessage(`{"h1":"100"}`),
		HeaderProtectionKey: bytes.Repeat([]byte{0x5c}, 32),
	}
	account.Settings.TunnelProfileGraceUntil = time.Now().UTC().Add(time.Hour)

	require.NoError(t, sqlStore.SaveAccount(ctx, account))
	require.Equal(t, headerKey, account.Settings.TunnelProfile.HeaderProtectionKey)
	require.Empty(
		t,
		account.Settings.TunnelProfile.EncryptedHeaderProtectionKey,
	)

	var raw types.AccountSettings
	require.NoError(
		t,
		sqlStore.db.Model(&types.Account{}).
			Where(idQueryCondition, account.Id).
			Take(&raw).Error,
	)
	require.NotNil(t, raw.Settings)
	require.NotNil(t, raw.Settings.TunnelProfile)
	require.Empty(t, raw.Settings.TunnelProfile.HeaderProtectionKey)
	require.NotEmpty(
		t,
		raw.Settings.TunnelProfile.EncryptedHeaderProtectionKey,
	)
	require.Empty(
		t,
		raw.Settings.TunnelProfilePending.HeaderProtectionKey,
	)
	require.NotEmpty(
		t,
		raw.Settings.TunnelProfilePending.EncryptedHeaderProtectionKey,
	)
	require.Empty(
		t,
		raw.Settings.TunnelProfilePrevious.HeaderProtectionKey,
	)
	require.NotEmpty(
		t,
		raw.Settings.TunnelProfilePrevious.EncryptedHeaderProtectionKey,
	)
	firstCiphertext := raw.Settings.TunnelProfile.EncryptedHeaderProtectionKey

	stored, err := sqlStore.GetAccount(ctx, account.Id)
	require.NoError(t, err)
	require.Equal(
		t,
		headerKey,
		stored.Settings.TunnelProfile.HeaderProtectionKey,
	)
	require.Empty(
		t,
		stored.Settings.TunnelProfile.EncryptedHeaderProtectionKey,
	)
	require.Len(
		t,
		stored.Settings.TunnelProfilePending.HeaderProtectionKey,
		32,
	)
	require.Empty(
		t,
		stored.Settings.TunnelProfilePending.EncryptedHeaderProtectionKey,
	)
	require.Len(
		t,
		stored.Settings.TunnelProfilePrevious.HeaderProtectionKey,
		32,
	)
	require.Empty(
		t,
		stored.Settings.TunnelProfilePrevious.EncryptedHeaderProtectionKey,
	)

	settings, err := sqlStore.GetAccountSettings(
		ctx,
		LockingStrengthNone,
		account.Id,
	)
	require.NoError(t, err)
	require.Equal(t, headerKey, settings.TunnelProfile.HeaderProtectionKey)

	settings.TunnelPolicy = types.TunnelAccountPolicyRequireAWG
	require.NoError(
		t,
		sqlStore.SaveAccountSettings(ctx, account.Id, settings),
	)
	require.Equal(t, headerKey, settings.TunnelProfile.HeaderProtectionKey)

	raw = types.AccountSettings{}
	require.NoError(
		t,
		sqlStore.db.Model(&types.Account{}).
			Where(idQueryCondition, account.Id).
			Take(&raw).Error,
	)
	require.Empty(t, raw.Settings.TunnelProfile.HeaderProtectionKey)
	require.NotEmpty(
		t,
		raw.Settings.TunnelProfile.EncryptedHeaderProtectionKey,
	)
	require.NotEqual(
		t,
		firstCiphertext,
		raw.Settings.TunnelProfile.EncryptedHeaderProtectionKey,
	)
}

func TestAWG3SettingsRequireDatastoreEncryption(t *testing.T) {
	ctx := context.Background()
	sqlStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	account := newAccountWithId(ctx, "awg3-no-key", "awg3-user", "")
	account.Settings.TunnelProfile = &types.TunnelProfile{
		ProtocolVersion:     "awg3",
		Revision:            1,
		Parameters:          json.RawMessage(`{"h1":"101"}`),
		HeaderProtectionKey: bytes.Repeat([]byte{0x6a}, 32),
	}

	require.Error(t, sqlStore.SaveAccount(ctx, account))
}
