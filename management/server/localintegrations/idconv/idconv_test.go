package idconv

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInt64(t *testing.T) {
	value, err := Int64(math.MaxInt64)
	require.NoError(t, err)
	require.Equal(t, int64(math.MaxInt64), value)

	_, err = Int64(math.MaxInt64 + 1)
	require.Error(t, err)
}

func TestInt(t *testing.T) {
	value, err := Int(42)
	require.NoError(t, err)
	require.Equal(t, 42, value)

	if strconv.IntSize == 64 {
		_, err = Int(math.MaxInt64 + 1)
	} else {
		_, err = Int(math.MaxInt32 + 1)
	}
	require.Error(t, err)
}
