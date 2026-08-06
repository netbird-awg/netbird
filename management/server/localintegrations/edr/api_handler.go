package edr

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const maxEDRRequestBody = 1 << 20

type apiHandler struct {
	service *Service
}

// RegisterAPIEndpoints mounts the paths already consumed by the upstream
// Dashboard and generated REST client.
func RegisterAPIEndpoints(service *Service, router *mux.Router) {
	handler := &apiHandler{service: service}
	for _, provider := range providers {
		base := "/integrations/edr/" + provider
		router.HandleFunc(base, handler.getIntegration(provider)).Methods(http.MethodGet, http.MethodOptions)
		router.HandleFunc(base, handler.createIntegration(provider)).Methods(http.MethodPost, http.MethodOptions)
		router.HandleFunc(base, handler.updateIntegration(provider)).Methods(http.MethodPut, http.MethodOptions)
		router.HandleFunc(base, handler.deleteIntegration(provider)).Methods(http.MethodDelete, http.MethodOptions)
	}
	router.HandleFunc("/peers/edr/bypassed", handler.listBypasses).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/peers/{peer-id}/edr/bypass", handler.bypass).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/peers/{peer-id}/edr/bypass", handler.revokeBypass).Methods(http.MethodDelete, http.MethodOptions)
}

func (h *apiHandler) getIntegration(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, userID, ok := edrRequestIdentity(w, r)
		if !ok {
			return
		}
		var result any
		var err error
		switch provider {
		case providerIntune:
			result, err = h.service.GetIntune(r.Context(), accountID, userID)
		case providerFalcon:
			result, err = h.service.GetFalcon(r.Context(), accountID, userID)
		case providerSentinelOne:
			result, err = h.service.GetSentinelOne(r.Context(), accountID, userID)
		case providerHuntress:
			result, err = h.service.GetHuntress(r.Context(), accountID, userID)
		case providerFleetDM:
			result, err = h.service.GetFleetDM(r.Context(), accountID, userID)
		default:
			err = status.Errorf(status.InvalidArgument, "unsupported EDR provider")
		}
		writeEDRResult(w, r, result, err)
	}
}

func (h *apiHandler) createIntegration(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, userID, ok := edrRequestIdentity(w, r)
		if !ok {
			return
		}
		result, err := h.decodeAndCreate(r, accountID, userID, provider)
		writeEDRResult(w, r, result, err)
	}
}

func (h *apiHandler) updateIntegration(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, userID, ok := edrRequestIdentity(w, r)
		if !ok {
			return
		}
		result, err := h.decodeAndUpdate(r, accountID, userID, provider)
		writeEDRResult(w, r, result, err)
	}
}

func (h *apiHandler) deleteIntegration(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID, userID, ok := edrRequestIdentity(w, r)
		if !ok {
			return
		}
		if err := h.service.Delete(r.Context(), accountID, userID, provider); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		util.WriteJSONObject(r.Context(), w, struct{}{})
	}
}

func (h *apiHandler) decodeAndCreate(
	r *http.Request,
	accountID, userID, provider string,
) (any, error) {
	switch provider {
	case providerIntune:
		var request api.EDRIntuneRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.CreateIntune(r.Context(), accountID, userID, request)
	case providerFalcon:
		var request api.EDRFalconRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.CreateFalcon(r.Context(), accountID, userID, request)
	case providerSentinelOne:
		var request api.EDRSentinelOneRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.CreateSentinelOne(r.Context(), accountID, userID, request)
	case providerHuntress:
		var request api.EDRHuntressRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.CreateHuntress(r.Context(), accountID, userID, request)
	case providerFleetDM:
		var request api.EDRFleetDMRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.CreateFleetDM(r.Context(), accountID, userID, request)
	default:
		return nil, status.Errorf(status.InvalidArgument, "unsupported EDR provider")
	}
}

func (h *apiHandler) decodeAndUpdate(
	r *http.Request,
	accountID, userID, provider string,
) (any, error) {
	switch provider {
	case providerIntune:
		var request api.EDRIntuneUpdateRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.UpdateIntune(r.Context(), accountID, userID, intuneRequestFromUpdate(request))
	case providerFalcon:
		var request api.EDRFalconUpdateRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.UpdateFalcon(r.Context(), accountID, userID, falconRequestFromUpdate(request))
	case providerSentinelOne:
		var request api.EDRSentinelOneUpdateRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.UpdateSentinelOne(r.Context(), accountID, userID, sentinelOneRequestFromUpdate(request))
	case providerHuntress:
		var request api.EDRHuntressUpdateRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.UpdateHuntress(r.Context(), accountID, userID, huntressRequestFromUpdate(request))
	case providerFleetDM:
		var request api.EDRFleetDMUpdateRequest
		if err := decodeEDRJSON(r, &request); err != nil {
			return nil, err
		}
		return h.service.UpdateFleetDM(r.Context(), accountID, userID, fleetDMRequestFromUpdate(request))
	default:
		return nil, status.Errorf(status.InvalidArgument, "unsupported EDR provider")
	}
}

func (h *apiHandler) bypass(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := edrRequestIdentity(w, r)
	if !ok {
		return
	}
	peerID := strings.TrimSpace(mux.Vars(r)["peer-id"])
	if peerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "peer ID is required"), w)
		return
	}
	result, err := h.service.BypassCompliance(r.Context(), accountID, userID, peerID)
	writeEDRResult(w, r, result, err)
}

func (h *apiHandler) revokeBypass(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := edrRequestIdentity(w, r)
	if !ok {
		return
	}
	peerID := strings.TrimSpace(mux.Vars(r)["peer-id"])
	if peerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "peer ID is required"), w)
		return
	}
	if err := h.service.RevokeBypass(r.Context(), accountID, userID, peerID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, struct{}{})
}

func (h *apiHandler) listBypasses(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := edrRequestIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.service.ListBypassedPeers(r.Context(), accountID, userID)
	writeEDRResult(w, r, result, err)
}

func edrRequestIdentity(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	auth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return "", "", false
	}
	return auth.AccountId, auth.UserId, true
}

func decodeEDRJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxEDRRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid EDR JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return status.Errorf(status.InvalidArgument, "request must contain one JSON object")
	}
	return nil
}

func writeEDRResult(w http.ResponseWriter, r *http.Request, value any, err error) {
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, value)
}
