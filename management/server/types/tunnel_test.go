package types

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util/crypt"
)

func TestTunnelProfileSensitiveDataRoundTrip(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)

	headerKey := bytes.Repeat([]byte{0x7c}, 32)
	profile := &TunnelProfile{
		ProtocolVersion:     TunnelProtocolAmneziaWG3,
		HeaderProtectionKey: bytes.Clone(headerKey),
	}

	require.NoError(t, profile.EncryptSensitiveData(fieldEncrypt))
	require.Empty(t, profile.HeaderProtectionKey)
	require.NotEmpty(t, profile.EncryptedHeaderProtectionKey)

	require.NoError(t, profile.DecryptSensitiveData(fieldEncrypt))
	require.Equal(t, headerKey, profile.HeaderProtectionKey)
	require.Empty(t, profile.EncryptedHeaderProtectionKey)
}

func TestTunnelProfileSensitiveDataRequiresEncryptionKey(t *testing.T) {
	profile := &TunnelProfile{
		ProtocolVersion:     TunnelProtocolAmneziaWG3,
		HeaderProtectionKey: bytes.Repeat([]byte{0x7c}, 32),
	}

	require.Error(t, profile.EncryptSensitiveData(nil))
}

func TestTunnelProfileSensitiveDataRejectsWrongLength(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)
	profile := &TunnelProfile{
		ProtocolVersion:     TunnelProtocolAmneziaWG3,
		HeaderProtectionKey: bytes.Repeat([]byte{0x7c}, 31),
	}

	require.Error(t, profile.EncryptSensitiveData(fieldEncrypt))
}

func TestTunnelProfileSensitiveDataRejectsMissingAWG3Key(t *testing.T) {
	profile := &TunnelProfile{
		ProtocolVersion: TunnelProtocolAmneziaWG3,
	}

	require.Error(t, profile.EncryptSensitiveData(nil))
	require.Error(t, profile.DecryptSensitiveData(nil))
}

func TestTunnelProfileSensitiveDataRejectsAWG2Key(t *testing.T) {
	profile := &TunnelProfile{
		ProtocolVersion:     TunnelProtocolAmneziaWG2,
		HeaderProtectionKey: bytes.Repeat([]byte{0x7c}, 32),
	}

	require.Error(t, profile.EncryptSensitiveData(nil))
}

func TestTunnelProfileSensitiveDataRejectsInvalidCiphertext(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)
	profile := &TunnelProfile{
		ProtocolVersion:              TunnelProtocolAmneziaWG3,
		EncryptedHeaderProtectionKey: "not-ciphertext",
	}

	require.Error(t, profile.DecryptSensitiveData(fieldEncrypt))
	require.Empty(t, profile.HeaderProtectionKey)
}
