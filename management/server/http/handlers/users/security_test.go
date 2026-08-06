package users

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestPasswordOnlyAppearsInCreationResponse(t *testing.T) {
	user := &types.UserInfo{
		ID:       "user-1",
		Role:     "user",
		Status:   "active",
		Password: "OneTimePassword123!",
	}

	regularResponse := toUserResponse(user, "admin-1")
	assert.Nil(t, regularResponse.Password)

	creationResponse := toUserCreationResponse(user, "admin-1")
	if assert.NotNil(t, creationResponse.Password) {
		assert.Equal(t, "OneTimePassword123!", *creationResponse.Password)
	}
}

func TestDecodeStrictJSONBodyRejectsAmbiguousOrOversizedInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "trailing object", body: `{"code":"123456"}{"code":"654321"}`},
		{name: "unknown field", body: `{"code":"123456","unexpected":true}`},
		{name: "oversized", body: `{"code":"` + strings.Repeat("1", maxSensitiveJSONBodyBytes) + `"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
			res := httptest.NewRecorder()
			var dst struct {
				Code string `json:"code"`
			}
			assert.Error(t, decodeStrictJSONBody(res, req, &dst))
		})
	}
}
