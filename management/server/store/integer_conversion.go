package store

import (
	"fmt"
	"math"
	"strconv"
)

func checkedIntToUint(field string, value int) (uint, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative: %d", field, value)
	}
	return uint(value), nil // #nosec G115 -- negative values are rejected above
}

func checkedInt64ToUint64(field string, value int64) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative: %d", field, value)
	}
	return uint64(value), nil // #nosec G115 -- negative values are rejected above
}

func checkedInt64ToUint(field string, value int64) (uint, error) {
	if value < 0 || (strconv.IntSize == 32 && value > math.MaxUint32) {
		return 0, fmt.Errorf("%s is outside the uint range: %d", field, value)
	}
	return uint(value), nil // #nosec G115 -- architecture-specific range is checked above
}

func checkedInt64ToUint16(field string, value int64) (uint16, error) {
	if value < 0 || value > math.MaxUint16 {
		return 0, fmt.Errorf("%s is outside the uint16 range: %d", field, value)
	}
	return uint16(value), nil // #nosec G115 -- uint16 range is checked above
}
