package eventstreaming

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const maxAPIRequestBody = 1 << 20

type apiHandler struct {
	service *Service
}

// RegisterAPIEndpoints mounts the routes used by the upstream Dashboard.
func RegisterAPIEndpoints(service *Service, router *mux.Router) {
	handler := &apiHandler{service: service}
	for _, base := range []string{"/integrations/event-streaming", "/event-streaming"} {
		router.HandleFunc(base, handler.create).Methods(http.MethodPost, http.MethodOptions)
		router.HandleFunc(base, handler.list).Methods(http.MethodGet, http.MethodOptions)
		router.HandleFunc(base+"/{id}", handler.get).Methods(http.MethodGet, http.MethodOptions)
		router.HandleFunc(base+"/{id}", handler.update).Methods(http.MethodPut, http.MethodOptions)
		router.HandleFunc(base+"/{id}", handler.delete).Methods(http.MethodDelete, http.MethodOptions)
	}
}

func (h *apiHandler) create(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	var request api.CreateIntegrationRequest
	if err := decodeJSON(r, &request); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.service.CreateIntegration(r.Context(), accountID, userID, request)
	writeResult(w, r, result, err)
}

func (h *apiHandler) list(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.service.ListIntegrations(r.Context(), accountID, userID)
	writeResult(w, r, result, err)
}

func (h *apiHandler) get(w http.ResponseWriter, r *http.Request) {
	accountID, userID, id, ok := requestParams(w, r)
	if !ok {
		return
	}
	result, err := h.service.GetIntegration(r.Context(), accountID, userID, id)
	writeResult(w, r, result, err)
}

func (h *apiHandler) update(w http.ResponseWriter, r *http.Request) {
	accountID, userID, id, ok := requestParams(w, r)
	if !ok {
		return
	}
	var request api.CreateIntegrationRequest
	if err := decodeJSON(r, &request); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.service.UpdateIntegration(r.Context(), accountID, userID, id, request)
	writeResult(w, r, result, err)
}

func (h *apiHandler) delete(w http.ResponseWriter, r *http.Request) {
	accountID, userID, id, ok := requestParams(w, r)
	if !ok {
		return
	}
	if err := h.service.DeleteIntegration(r.Context(), accountID, userID, id); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, struct{}{})
}

func requestIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	auth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	return auth.AccountId, auth.UserId, true
}

func requestParams(w http.ResponseWriter, r *http.Request) (string, string, uint64, bool) {
	accountID, userID, ok := requestIdentity(w, r)
	if !ok {
		return "", "", 0, false
	}
	id, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil || id == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid integration id"), w)
		return "", "", 0, false
	}
	return accountID, userID, id, true
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxAPIRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return status.Errorf(status.InvalidArgument, "request must contain a single JSON object")
	}
	return nil
}

func writeResult(w http.ResponseWriter, r *http.Request, value any, err error) {
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, value)
}
