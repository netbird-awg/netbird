package idp

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePasswordUsesRequestedComplexity(t *testing.T) {
	password, err := GeneratePassword(32, 3, 4, 5)
	require.NoError(t, err)
	require.Len(t, password, 32)

	var specials, digits, uppercase int
	for _, char := range password {
		switch {
		case strings.ContainsRune(specialCharSet, char):
			specials++
		case unicode.IsDigit(char):
			digits++
		case unicode.IsUpper(char):
			uppercase++
		}
	}
	assert.GreaterOrEqual(t, specials, 3)
	assert.GreaterOrEqual(t, digits, 4)
	assert.GreaterOrEqual(t, uppercase, 5)
}

func TestGeneratePasswordRejectsImpossibleRequirements(t *testing.T) {
	_, err := GeneratePassword(8, 4, 4, 4)
	require.Error(t, err)
}
