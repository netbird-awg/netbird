package ldapsync

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/idp/dex"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type httpHandler struct {
	service *Service
}

// RegisterEndpoints mounts the local integration API under the existing
// authenticated /api router.
func RegisterEndpoints(service *Service, router *mux.Router, syncEnabled bool) {
	h := &httpHandler{service: service}
	router.HandleFunc("/identity-providers/{idpId}/test", h.testConnector).Methods(http.MethodPost, http.MethodOptions)
	if !syncEnabled {
		return
	}

	base := "/local/integrations/ldap-sync"
	router.HandleFunc(base, h.listConfigs).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}", h.getConfig).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}", h.saveConfig).Methods(http.MethodPut, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/preview", h.preview).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/runs", h.createRun).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/runs", h.listRuns).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/runs/{runId}", h.getRun).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/runs/{runId}/confirm", h.confirmRun).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/runs/{runId}/cancel", h.cancelRun).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/pause", h.pause).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{connectorId}/resume", h.resume).Methods(http.MethodPost, http.MethodOptions)
}

func (h *httpHandler) testConnector(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	response, err := h.service.TestConnector(r.Context(), accountID, mux.Vars(r)["idpId"], userID)
	if err != nil {
		var diagnosticErr *dex.LDAPDiagnosticError
		if errors.As(err, &diagnosticErr) {
			writeJSONStatus(w, http.StatusUnprocessableEntity, ConnectorTestErrorResponse{
				Status: "failed",
				Stage:  diagnosticErr.Stage,
				Code:   diagnosticErr.Code,
				Checks: diagnosticErr.Checks,
			})
			return
		}
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, response)
}

func (h *httpHandler) listConfigs(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	configs, err := h.service.ListConfigs(r.Context(), accountID, userID)
	writeResult(w, r, configs, err)
}

func (h *httpHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	config, err := h.service.GetConfig(r.Context(), accountID, mux.Vars(r)["connectorId"], userID)
	writeResult(w, r, config, err)
}

func (h *httpHandler) saveConfig(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	var request ConfigRequest
	if err := decodeJSONBody(r, &request, false); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	config, err := h.service.SaveConfig(r.Context(), accountID, mux.Vars(r)["connectorId"], userID, request)
	writeResult(w, r, config, err)
}

func (h *httpHandler) preview(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	preview, err := h.service.Preview(r.Context(), accountID, mux.Vars(r)["connectorId"], userID)
	writeResult(w, r, preview, err)
}

func (h *httpHandler) createRun(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	var request RunRequest
	if err := decodeJSONBody(r, &request, true); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	run, err := h.service.QueueRun(r.Context(), accountID, mux.Vars(r)["connectorId"], userID, request.ConfirmationToken)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, run)
}

func (h *httpHandler) listRuns(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	limit, err := queryInt(r, "limit", defaultRunPageSize)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	runs, serviceErr := h.service.ListRuns(r.Context(), accountID, mux.Vars(r)["connectorId"], userID, offset, limit)
	writeResult(w, r, runs, serviceErr)
}

func (h *httpHandler) getRun(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	vars := mux.Vars(r)
	run, err := h.service.GetRun(r.Context(), accountID, vars["connectorId"], vars["runId"], userID)
	writeResult(w, r, run, err)
}

func (h *httpHandler) confirmRun(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	var request RunRequest
	if err := decodeJSONBody(r, &request, false); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	vars := mux.Vars(r)
	run, err := h.service.ConfirmRun(r.Context(), accountID, vars["connectorId"], vars["runId"], userID, request.ConfirmationToken)
	writeResult(w, r, run, err)
}

func (h *httpHandler) cancelRun(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	vars := mux.Vars(r)
	run, err := h.service.CancelRun(r.Context(), accountID, vars["connectorId"], vars["runId"], userID)
	writeResult(w, r, run, err)
}

func (h *httpHandler) pause(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	config, err := h.service.Pause(r.Context(), accountID, mux.Vars(r)["connectorId"], userID)
	writeResult(w, r, config, err)
}

func (h *httpHandler) resume(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	config, err := h.service.Resume(r.Context(), accountID, mux.Vars(r)["connectorId"], userID)
	writeResult(w, r, config, err)
}

func requestIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	auth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	return auth.AccountId, auth.UserId, true
}

func decodeJSONBody(r *http.Request, target any, allowEmpty bool) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return nil
		}
		return status.Errorf(status.InvalidArgument, "invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return status.Errorf(status.InvalidArgument, "request must contain a single JSON object")
	}
	return nil
}

func queryInt(r *http.Request, name string, fallback int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, status.Errorf(status.InvalidArgument, "%s must be an integer", name)
	}
	return value, nil
}

func writeResult(w http.ResponseWriter, r *http.Request, result any, err error) {
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, result)
}

func writeJSONStatus(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
