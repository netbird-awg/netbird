package auth

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/common"
)

func TestLoginFlagFromProto(t *testing.T) {
	for _, expected := range []common.LoginFlag{
		common.LoginFlagPromptLogin,
		common.LoginFlagMaxAge0,
		common.LoginFlagNone,
	} {
		actual, err := loginFlagFromProto(uint32(expected))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}

	_, err := loginFlagFromProto(math.MaxUint32)
	require.Error(t, err)
}
