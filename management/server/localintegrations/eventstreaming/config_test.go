package eventstreaming

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
	"github.com/netbirdio/netbird/management/server/outbound"
	"github.com/netbirdio/netbird/util/crypt"
)

type staticResolver struct {
	addresses map[string][]netip.Addr
}

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r.addresses[host], nil
}

func testValidator(t *testing.T, host string, address netip.Addr) *outbound.Validator {
	t.Helper()
	validator, err := outbound.NewValidator(
		staticResolver{addresses: map[string][]netip.Addr{host: {address}}},
		nil,
		nil,
	)
	require.NoError(t, err)
	return validator
}

func TestNormalizeGenericHTTPConfigRejectsPrivateDestination(t *testing.T) {
	validator := testValidator(t, "internal.example", netip.MustParseAddr("10.0.0.10"))
	_, err := normalizeConfig(context.Background(), validator, "generic_http", map[string]string{
		"url": "https://internal.example/events",
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowlisted")
}

func TestNormalizeGenericHTTPConfigRejectsManagedAndInjectedHeaders(t *testing.T) {
	validator := testValidator(t, "events.example", netip.MustParseAddr("203.0.113.10"))
	tests := []string{
		`{"Host":"attacker.example"}`,
		"{\"X-Test\":\"safe\\r\\ninjected: true\"}",
	}
	for _, headers := range tests {
		_, err := normalizeConfig(context.Background(), validator, "generic_http", map[string]string{
			"url":     "https://events.example/ingest",
			"headers": headers,
		}, nil)
		require.Error(t, err)
	}
}

func TestMaskConfigMasksAllSensitiveValues(t *testing.T) {
	masked := maskConfig(map[string]string{
		"api_key":    "datadog-secret",
		"secret_key": "aws-secret",
		"url":        "https://events.example/ingest",
		"headers":    `{"Authorization":"Bearer secret","X-API-Key":"secret","X-Tenant":"tenant-a"}`,
	})
	require.Equal(t, maskedSecret, masked["api_key"])
	require.Equal(t, maskedSecret, masked["secret_key"])
	require.NotContains(t, masked["headers"], "Bearer secret")
	require.NotContains(t, masked["headers"], `"secret"`)
	require.Contains(t, masked["headers"], "tenant-a")
}

func TestMergeMaskedHeadersPreservesStoredSecrets(t *testing.T) {
	merged, err := mergeMaskedHeaders(
		`{"Authorization":"Bearer original","X-Tenant":"old"}`,
		`{"Authorization":"********","X-Tenant":"new"}`,
	)
	require.NoError(t, err)
	require.Contains(t, merged, "Bearer original")
	require.Contains(t, merged, "new")
}

func TestStoredConfigurationIsEncryptedAndAPIResponseIsMasked(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	encryptor, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	service := &Service{encryptor: encryptor}
	encrypted, err := service.encryptConfig(map[string]string{
		"api_key": "plain-api-secret",
		"api_url": "https://http-intake.logs.datadoghq.com/api/v2/logs",
	})
	require.NoError(t, err)
	require.NotContains(t, encrypted, "plain-api-secret")

	response, err := service.integrationResponse(&eventmodel.Integration{
		ID:              1,
		AccountID:       "account-1",
		Platform:        "datadog",
		Enabled:         true,
		EncryptedConfig: encrypted,
	})
	require.NoError(t, err)
	require.Equal(t, maskedSecret, (*response.Config)["api_key"])
	require.NotContains(t, (*response.Config)["api_key"], "plain-api-secret")
}

func TestRenderGenericBodyEscapesEventValues(t *testing.T) {
	event := StreamEvent{
		ID:          7,
		Timestamp:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		Code:        "peer.update",
		Message:     "renamed \"peer\"\nnext",
		InitiatorID: "user-1",
		TargetID:    "peer-1",
		AccountID:   "account-1",
		Meta:        map[string]any{"ip": "100.64.0.1"},
	}
	body, err := renderGenericBody(
		`{"id":"{{.ID}}","message":"{{.Message}}","meta":"{{.Meta}}"}`,
		event,
		nil,
	)
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{"id":"7","message":"renamed \"peer\"\nnext","meta":"{\"ip\":\"100.64.0.1\"}"}`,
		string(body),
	)
}

type recordingHTTPClient struct {
	request *http.Request
	body    string
	status  int
	err     error
}

func (c *recordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	c.request = request
	if request.Body != nil {
		data := make([]byte, request.ContentLength)
		_, _ = request.Body.Read(data)
		c.body = string(data)
	}
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		StatusCode: c.status,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    request,
	}, nil
}

func TestPostJSONUsesValidatedDestinationAndClassifiesResponses(t *testing.T) {
	validator := testValidator(t, "events.example", netip.MustParseAddr("203.0.113.10"))
	client := &recordingHTTPClient{status: http.StatusTooManyRequests}
	service := &Service{validator: validator, httpClient: client}
	err := service.postJSON(
		context.Background(),
		"https://events.example/ingest",
		map[string]string{"X-API-Key": "secret"},
		[]byte(`{"ok":true}`),
	)
	require.Error(t, err)
	require.True(t, isRetryable(err))
	require.Equal(t, "secret", client.request.Header.Get("X-API-Key"))
	require.Equal(t, `{"ok":true}`, client.body)

	client.status = http.StatusBadRequest
	err = service.postJSON(
		context.Background(),
		"https://events.example/ingest",
		nil,
		[]byte(`{}`),
	)
	require.Error(t, err)
	require.False(t, isRetryable(err))
}

func TestSanitizeDeliveryErrorRedactsCredentials(t *testing.T) {
	message := sanitizeDeliveryError(&net.DNSError{
		Err: "Authorization=Bearer-secret api_key:top-secret",
	})
	require.NotContains(t, strings.ToLower(message), "bearer-secret")
	require.NotContains(t, strings.ToLower(message), "top-secret")
}
