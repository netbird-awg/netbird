package idconv

import (
	"fmt"
	"math"
	"strconv"
)

// Int64 converts a database identifier without allowing it to wrap into a
// negative API identifier.
func Int64(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("identifier %d exceeds int64", value)
	}
	return int64(value), nil
}

// Int converts a database identifier to the platform-sized representation
// used by IntegrationReference.
func Int(value uint64) (int, error) {
	if strconv.IntSize == 32 && value > math.MaxInt32 {
		return 0, fmt.Errorf("identifier %d exceeds int32", value)
	}
	if strconv.IntSize == 64 && value > math.MaxInt64 {
		return 0, fmt.Errorf("identifier %d exceeds int64", value)
	}
	return int(value), nil
}
