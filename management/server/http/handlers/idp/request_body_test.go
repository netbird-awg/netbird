package idp

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeStrictJSONBodyRejectsAmbiguousOrOversizedInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "trailing object", body: `{"name":"ldap"}{"name":"other"}`},
		{name: "unknown field", body: `{"name":"ldap","unexpected":true}`},
		{name: "oversized", body: `{"root_ca":"` + strings.Repeat("a", maxIdentityProviderJSONBodyBytes) + `"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
			res := httptest.NewRecorder()
			var dst struct {
				Name   string `json:"name"`
				RootCA string `json:"root_ca"`
			}
			require.Error(t, decodeStrictJSONBody(res, req, &dst))
		})
	}
}
