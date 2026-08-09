package accounts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

type tunnelLifecycleManagerStub struct {
	getResult    *managementtunnel.LifecycleResult
	getErr       error
	updateResult *managementtunnel.LifecycleResult
	updateErr    error
	updates      int
	request      managementtunnel.LifecycleRequest
}

type tunnelLifecycleReplayManager struct {
	settings *types.Settings
	now      time.Time
	updates  int
}

func (m *tunnelLifecycleReplayManager) GetTunnelLifecycle(
	context.Context,
	string,
	string,
) (*managementtunnel.LifecycleResult, error) {
	return lifecycleReplayResult(m.settings, m.now, false), nil
}

func (m *tunnelLifecycleReplayManager) UpdateTunnelLifecycle(
	_ context.Context,
	_, _ string,
	request managementtunnel.LifecycleRequest,
) (*managementtunnel.LifecycleResult, error) {
	m.updates++
	updated, changed, err := managementtunnel.ApplyLifecycle(
		m.settings,
		request,
		managementtunnel.Readiness{},
		m.now,
	)
	if err != nil {
		return nil, err
	}
	m.settings = updated
	return lifecycleReplayResult(updated, m.now, changed), nil
}

func (s *tunnelLifecycleManagerStub) GetTunnelLifecycle(
	context.Context,
	string,
	string,
) (*managementtunnel.LifecycleResult, error) {
	return s.getResult, s.getErr
}

func (s *tunnelLifecycleManagerStub) UpdateTunnelLifecycle(
	_ context.Context,
	_, _ string,
	request managementtunnel.LifecycleRequest,
) (*managementtunnel.LifecycleResult, error) {
	s.updates++
	s.request = request
	return s.updateResult, s.updateErr
}

func TestTunnelLifecyclePatchRejectsUnknownFields(t *testing.T) {
	manager := &tunnelLifecycleManagerStub{}
	recorder := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		`{"action":"stage","protocol_version":"awg3","parameters":{}}`,
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if manager.updates != 0 {
		t.Fatal("manager was called for an ambiguous request")
	}
	if !strings.Contains(recorder.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unexpected error body: %s", recorder.Body.String())
	}
}

func TestTunnelLifecyclePatchAcceptsEveryActionShape(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "stage", body: `{"action":"stage","protocol_version":"awg2"}`},
		{name: "activate", body: `{"action":"activate","target_revision":1}`},
		{name: "cancel", body: `{"action":"cancel_pending","target_revision":1}`},
		{name: "rollback", body: `{"action":"rollback","target_revision":1}`},
		{name: "set policy", body: `{"action":"set_policy","policy":"standard"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &tunnelLifecycleManagerStub{
				updateResult: lifecycleHandlerResult(time.Now().UTC()),
			}
			recorder := executeTunnelLifecycleRequest(
				t,
				manager,
				http.MethodPatch,
				test.body,
			)
			if recorder.Code != http.StatusOK || manager.updates != 1 {
				t.Fatalf("valid action rejected: %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestTunnelLifecyclePatchReplaysCancelWithoutExpectedRevision(t *testing.T) {
	now := time.Now().UTC()
	manager := &tunnelLifecycleReplayManager{
		settings: &types.Settings{
			TunnelPolicy: types.TunnelAccountPolicyStandard,
			TunnelProfile: lifecycleHandlerProfile(
				1,
				now.Add(-time.Hour),
				nil,
				"",
			),
			TunnelProfilePending: lifecycleHandlerProfile(
				2,
				now,
				nil,
				"",
			),
		},
		now: now,
	}
	body := `{"action":"cancel_pending","target_revision":2}`

	first := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		body,
	)
	if first.Code != http.StatusOK || manager.settings.TunnelProfilePending != nil {
		t.Fatalf("first cancel = %d %s", first.Code, first.Body.String())
	}
	afterCancel := manager.settings.Copy()

	replayed := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		body,
	)
	if replayed.Code != http.StatusOK || manager.updates != 2 ||
		!reflect.DeepEqual(afterCancel, manager.settings) {
		t.Fatalf("cancel replay = %d %s", replayed.Code, replayed.Body.String())
	}
}

func TestTunnelLifecyclePatchRedactsEveryProfileSecret(t *testing.T) {
	now := time.Now().UTC()
	activeSecret := bytes.Repeat([]byte{0x11}, 32)
	pendingSecret := bytes.Repeat([]byte{0x22}, 32)
	previousSecret := bytes.Repeat([]byte{0x33}, 32)
	result := &managementtunnel.LifecycleResult{
		Settings: &types.Settings{
			TunnelPolicy: types.TunnelAccountPolicyPreferAWG,
			TunnelProfile: lifecycleHandlerProfile(
				1,
				now,
				activeSecret,
				"active-ciphertext",
			),
			TunnelProfilePending: lifecycleHandlerProfile(
				2,
				now,
				pendingSecret,
				"pending-ciphertext",
			),
			TunnelProfilePrevious: lifecycleHandlerProfile(
				3,
				now,
				previousSecret,
				"previous-ciphertext",
			),
			TunnelProfileGraceUntil: now.Add(time.Hour),
		},
		Readiness: managementtunnel.Readiness{
			State:           managementtunnel.ReadinessWaiting,
			Eligible:        2,
			Ready:           1,
			Waiting:         1,
			ExcludedOffline: 3,
			Incompatible:    4,
			ObservedAt:      now,
			ErrorCounts: map[string]int{
				"clock_skew": 1,
			},
		},
	}
	manager := &tunnelLifecycleManagerStub{updateResult: result}
	recorder := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		`{"action":"set_policy","policy":"prefer_awg"}`,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, secret := range []string{
		base64.StdEncoding.EncodeToString(activeSecret),
		base64.StdEncoding.EncodeToString(pendingSecret),
		base64.StdEncoding.EncodeToString(previousSecret),
		"active-ciphertext",
		"pending-ciphertext",
		"previous-ciphertext",
		"header_protection_key",
		"encrypted_header_protection_key",
		"parameters",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("response exposed %q: %s", secret, body)
		}
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["active"] == nil || response["pending"] == nil ||
		response["previous"] == nil {
		t.Fatalf("redacted profile references missing: %s", body)
	}
}

func TestTunnelLifecyclePatchSerializesTypedConflict(t *testing.T) {
	manager := &tunnelLifecycleManagerStub{
		updateErr: managementtunnel.NewLifecycleError(
			managementtunnel.LifecycleErrorStaleTargetRevision,
			"target tunnel revision is stale",
		),
	}
	recorder := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		`{"action":"activate","target_revision":7}`,
	)
	if recorder.Code != http.StatusConflict ||
		!strings.Contains(
			recorder.Body.String(),
			`"code":"stale_target_revision"`,
		) {
		t.Fatalf("unexpected conflict response: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestTunnelLifecyclePatchGenericErrorIsRedacted(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	manager := &tunnelLifecycleManagerStub{
		updateErr: errors.New("storage failure " + secret),
	}
	recorder := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		`{"action":"set_policy","policy":"standard"}`,
	)
	if recorder.Code != http.StatusInternalServerError ||
		strings.Contains(recorder.Body.String(), secret) ||
		!strings.Contains(recorder.Body.String(), "internal server error") {
		t.Fatalf("generic error response leaked details: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestTunnelLifecycleManagerErrorsAreRedactedFromBodyAndLogs(t *testing.T) {
	plaintext := "plain-lifecycle-secret"
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	ciphertext := "encrypted-lifecycle-ciphertext"
	injected := strings.Join([]string{plaintext, encoded, ciphertext}, " ")
	tests := []struct {
		name       string
		method     string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "get generic",
			method:     http.MethodGet,
			err:        errors.New(injected),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "internal server error",
		},
		{
			name:       "get permission",
			method:     http.MethodGet,
			err:        status.Errorf(status.PermissionDenied, "%s", injected),
			wantStatus: http.StatusForbidden,
			wantBody:   "permission denied",
		},
		{
			name:       "patch generic",
			method:     http.MethodPatch,
			err:        errors.New(injected),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "internal server error",
		},
		{
			name:       "patch permission",
			method:     http.MethodPatch,
			err:        status.Errorf(status.PermissionDenied, "%s", injected),
			wantStatus: http.StatusForbidden,
			wantBody:   "permission denied",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := log.StandardLogger()
			originalOutput := logger.Out
			logger.SetOutput(&logs)
			t.Cleanup(func() {
				logger.SetOutput(originalOutput)
			})

			manager := &tunnelLifecycleManagerStub{}
			if test.method == http.MethodGet {
				manager.getErr = test.err
			} else {
				manager.updateErr = test.err
			}
			recorder := executeTunnelLifecycleManagerErrorRequest(
				t,
				manager,
				test.method,
			)
			if recorder.Code != test.wantStatus ||
				!strings.Contains(recorder.Body.String(), test.wantBody) {
				t.Fatalf(
					"response = %d %s",
					recorder.Code,
					recorder.Body.String(),
				)
			}
			for _, marker := range []string{plaintext, encoded, ciphertext} {
				if strings.Contains(recorder.Body.String(), marker) ||
					strings.Contains(logs.String(), marker) {
					t.Fatalf(
						"manager error exposed %q: body=%s logs=%s",
						marker,
						recorder.Body.String(),
						logs.String(),
					)
				}
			}
		})
	}
}

func TestTunnelLifecyclePatchRejectsTrailingJSON(t *testing.T) {
	manager := &tunnelLifecycleManagerStub{}
	recorder := executeTunnelLifecycleRequest(
		t,
		manager,
		http.MethodPatch,
		`{"action":"set_policy","policy":"standard"}{}`,
	)
	if recorder.Code != http.StatusBadRequest || manager.updates != 0 {
		t.Fatalf("trailing JSON accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestTunnelLifecyclePatchRejectsInvalidRevisions(t *testing.T) {
	for _, body := range []string{
		`{"action":"activate","target_revision":0}`,
		`{"action":"stage","protocol_version":"awg2","expected_active_revision":-1}`,
		`{"action":"stage","protocol_version":"awg2","expected_pending_revision":-1}`,
	} {
		manager := &tunnelLifecycleManagerStub{}
		recorder := executeTunnelLifecycleRequest(
			t,
			manager,
			http.MethodPatch,
			body,
		)
		if recorder.Code != http.StatusBadRequest || manager.updates != 0 ||
			!strings.Contains(recorder.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("invalid revision accepted: %d %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestTunnelLifecyclePatchRequiresAuthentication(t *testing.T) {
	manager := &tunnelLifecycleManagerStub{}
	router := mux.NewRouter()
	handler := &tunnelLifecycleHandler{manager: manager}
	router.HandleFunc(
		"/accounts/{accountId}/tunnel",
		handler.patch,
	).Methods(http.MethodPatch)
	req := httptest.NewRequest(
		http.MethodPatch,
		"/accounts/account/tunnel",
		strings.NewReader(`{"action":"set_policy","policy":"standard"}`),
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized || manager.updates != 0 {
		t.Fatalf(
			"unauthenticated request = %d %s",
			recorder.Code,
			recorder.Body.String(),
		)
	}
}

func executeTunnelLifecycleRequest(
	t *testing.T,
	manager tunnelLifecycleManager,
	method,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	router := mux.NewRouter()
	handler := &tunnelLifecycleHandler{manager: manager}
	router.HandleFunc("/accounts/{accountId}/tunnel", handler.patch).Methods(method)
	req := httptest.NewRequest(method, "/accounts/account/tunnel", strings.NewReader(body))
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		AccountId: "account",
		UserId:    "admin",
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func executeTunnelLifecycleManagerErrorRequest(
	t *testing.T,
	manager tunnelLifecycleManager,
	method string,
) *httptest.ResponseRecorder {
	t.Helper()
	router := mux.NewRouter()
	handler := &tunnelLifecycleHandler{manager: manager}
	router.HandleFunc("/accounts/{accountId}/tunnel", handler.get).
		Methods(http.MethodGet)
	router.HandleFunc("/accounts/{accountId}/tunnel", handler.patch).
		Methods(http.MethodPatch)
	body := ""
	if method == http.MethodPatch {
		body = `{"action":"set_policy","policy":"standard"}`
	}
	req := httptest.NewRequest(
		method,
		"/accounts/account/tunnel",
		strings.NewReader(body),
	)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
		AccountId: "account",
		UserId:    "admin",
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func lifecycleHandlerProfile(
	revision uint64,
	now time.Time,
	plaintext []byte,
	ciphertext string,
) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion:              types.TunnelProtocolAmneziaWG3,
		Revision:                     revision,
		Parameters:                   json.RawMessage(`{"secret_parameter":"do-not-expose"}`),
		HeaderProtectionKey:          plaintext,
		EncryptedHeaderProtectionKey: ciphertext,
		UpdatedAt:                    now,
	}
}

func lifecycleHandlerResult(now time.Time) *managementtunnel.LifecycleResult {
	return &managementtunnel.LifecycleResult{
		Settings: &types.Settings{},
		Readiness: managementtunnel.Readiness{
			State:       managementtunnel.ReadinessNotStaged,
			ObservedAt:  now,
			ErrorCounts: map[string]int{},
		},
	}
}

func lifecycleReplayResult(
	settings *types.Settings,
	now time.Time,
	changed bool,
) *managementtunnel.LifecycleResult {
	return &managementtunnel.LifecycleResult{
		Settings: settings,
		Changed:  changed,
		Readiness: managementtunnel.Readiness{
			State:       managementtunnel.ReadinessNotStaged,
			ObservedAt:  now,
			ErrorCounts: map[string]int{},
		},
	}
}
