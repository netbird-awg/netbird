package scim

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

// RegisterAPIEndpoints mounts Dashboard-compatible configuration routes under
// the existing authenticated /api router.
func RegisterAPIEndpoints(service *Service, router *mux.Router) {
	handler := &apiHandler{service: service}
	base := "/integrations/scim-idp"
	router.HandleFunc(base, handler.create).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base, handler.list).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{id}", handler.get).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(base+"/{id}", handler.update).Methods(http.MethodPut, http.MethodOptions)
	router.HandleFunc(base+"/{id}", handler.delete).Methods(http.MethodDelete, http.MethodOptions)
	router.HandleFunc(base+"/{id}/token", handler.regenerateToken).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc(base+"/{id}/logs", handler.logs).Methods(http.MethodGet, http.MethodOptions)
}

func (h *apiHandler) create(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := scimRequestIdentity(w, r)
	if !ok {
		return
	}
	var request api.CreateScimIntegrationRequest
	if err := decodeSCIMJSON(r, &request, false); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.service.CreateIntegration(r.Context(), accountID, userID, request)
	writeSCIMResult(w, r, result, err)
}

func (h *apiHandler) list(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := scimRequestIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.service.ListIntegrations(r.Context(), accountID, userID)
	writeSCIMResult(w, r, result, err)
}

func (h *apiHandler) get(w http.ResponseWriter, r *http.Request) {
	accountID, userID, integrationID, ok := scimRequestParams(w, r)
	if !ok {
		return
	}
	result, err := h.service.GetIntegration(r.Context(), accountID, userID, integrationID)
	writeSCIMResult(w, r, result, err)
}

func (h *apiHandler) update(w http.ResponseWriter, r *http.Request) {
	accountID, userID, integrationID, ok := scimRequestParams(w, r)
	if !ok {
		return
	}
	var request UpdateIntegrationRequest
	if err := decodeSCIMJSON(r, &request, false); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	result, err := h.service.UpdateIntegration(r.Context(), accountID, userID, integrationID, request)
	writeSCIMResult(w, r, result, err)
}

func (h *apiHandler) delete(w http.ResponseWriter, r *http.Request) {
	accountID, userID, integrationID, ok := scimRequestParams(w, r)
	if !ok {
		return
	}
	if err := h.service.DeleteIntegration(r.Context(), accountID, userID, integrationID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, struct{}{})
}

func (h *apiHandler) regenerateToken(w http.ResponseWriter, r *http.Request) {
	accountID, userID, integrationID, ok := scimRequestParams(w, r)
	if !ok {
		return
	}
	result, err := h.service.RegenerateToken(r.Context(), accountID, userID, integrationID)
	writeSCIMResult(w, r, result, err)
}

func (h *apiHandler) logs(w http.ResponseWriter, r *http.Request) {
	accountID, userID, integrationID, ok := scimRequestParams(w, r)
	if !ok {
		return
	}
	result, err := h.service.ListLogs(r.Context(), accountID, userID, integrationID)
	writeSCIMResult(w, r, result, err)
}

func scimRequestIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	auth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	return auth.AccountId, auth.UserId, true
}

func scimRequestParams(w http.ResponseWriter, r *http.Request) (string, string, uint64, bool) {
	accountID, userID, ok := scimRequestIdentity(w, r)
	if !ok {
		return "", "", 0, false
	}
	integrationID, err := strconv.ParseUint(mux.Vars(r)["id"], 10, 64)
	if err != nil || integrationID == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid integration id"), w)
		return "", "", 0, false
	}
	return accountID, userID, integrationID, true
}

func decodeSCIMJSON(r *http.Request, target any, allowEmpty bool) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxAPIRequestBody))
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

func writeSCIMResult(w http.ResponseWriter, r *http.Request, value any, err error) {
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, value)
}
