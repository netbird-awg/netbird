package store

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckedIntegerConversions(t *testing.T) {
	t.Run("int to uint", func(t *testing.T) {
		value, err := checkedIntToUint("id", 42)
		require.NoError(t, err)
		require.Equal(t, uint(42), value)
		_, err = checkedIntToUint("id", -1)
		require.Error(t, err)
	})

	t.Run("int64 to uint64", func(t *testing.T) {
		value, err := checkedInt64ToUint64("serial", math.MaxInt64)
		require.NoError(t, err)
		require.Equal(t, uint64(math.MaxInt64), value)
		_, err = checkedInt64ToUint64("serial", -1)
		require.Error(t, err)
	})

	t.Run("int64 to uint", func(t *testing.T) {
		value, err := checkedInt64ToUint("geoname", 42)
		require.NoError(t, err)
		require.Equal(t, uint(42), value)
		_, err = checkedInt64ToUint("geoname", -1)
		require.Error(t, err)
	})

	t.Run("int64 to uint16", func(t *testing.T) {
		value, err := checkedInt64ToUint16("port", math.MaxUint16)
		require.NoError(t, err)
		require.Equal(t, uint16(math.MaxUint16), value)
		_, err = checkedInt64ToUint16("port", math.MaxUint16+1)
		require.Error(t, err)
	})
}
