package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const maxTunnelLifecycleRequestBytes = 16 * 1024

type tunnelLifecycleManager interface {
	GetTunnelLifecycle(
		ctx context.Context,
		accountID,
		userID string,
	) (*managementtunnel.LifecycleResult, error)
	UpdateTunnelLifecycle(
		ctx context.Context,
		accountID,
		userID string,
		request managementtunnel.LifecycleRequest,
	) (*managementtunnel.LifecycleResult, error)
}

type tunnelLifecycleHandler struct {
	manager tunnelLifecycleManager
}

func addTunnelLifecycleEndpoints(
	accountManager account.Manager,
	router *mux.Router,
) {
	handler := &tunnelLifecycleHandler{manager: accountManager}
	router.HandleFunc(
		"/accounts/{accountId}/tunnel",
		handler.get,
	).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc(
		"/accounts/{accountId}/tunnel",
		handler.patch,
	).Methods(http.MethodPatch, http.MethodOptions)
}

func (h *tunnelLifecycleHandler) get(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := tunnelLifecycleRequestIdentity(w, r)
	if !ok {
		return
	}
	result, err := h.manager.GetTunnelLifecycle(
		r.Context(),
		accountID,
		userID,
	)
	if err != nil {
		writeTunnelLifecycleManagerError(r.Context(), w, err)
		return
	}
	util.WriteJSONObject(r.Context(), w, toAPITunnelLifecycle(result))
}

func (h *tunnelLifecycleHandler) patch(w http.ResponseWriter, r *http.Request) {
	accountID, userID, ok := tunnelLifecycleRequestIdentity(w, r)
	if !ok {
		return
	}
	var request api.TunnelLifecycleRequest
	if err := decodeTunnelLifecycleRequest(w, r, &request); err != nil {
		writeTunnelLifecycleError(
			w,
			managementtunnel.LifecycleErrorInvalidRequest,
			"invalid tunnel lifecycle request",
			http.StatusBadRequest,
		)
		return
	}
	domainRequest, err := toTunnelLifecycleRequest(request)
	if err != nil {
		writeTunnelLifecycleError(
			w,
			managementtunnel.LifecycleErrorInvalidRequest,
			err.Error(),
			http.StatusBadRequest,
		)
		return
	}
	result, err := h.manager.UpdateTunnelLifecycle(
		r.Context(),
		accountID,
		userID,
		domainRequest,
	)
	if err != nil {
		var lifecycleErr *managementtunnel.LifecycleError
		if errors.As(err, &lifecycleErr) {
			statusCode := http.StatusConflict
			if lifecycleErr.Code == managementtunnel.LifecycleErrorInvalidRequest {
				statusCode = http.StatusBadRequest
			}
			writeTunnelLifecycleError(
				w,
				lifecycleErr.Code,
				lifecycleErr.Message,
				statusCode,
			)
			return
		}
		writeTunnelLifecycleManagerError(r.Context(), w, err)
		return
	}
	util.WriteJSONObject(r.Context(), w, toAPITunnelLifecycle(result))
}

func tunnelLifecycleRequestIdentity(
	w http.ResponseWriter,
	r *http.Request,
) (string, string, bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		writeTunnelLifecycleManagerError(
			r.Context(),
			w,
			status.Errorf(status.Unauthorized, "authentication required"),
		)
		return "", "", false
	}
	accountID := mux.Vars(r)["accountId"]
	if accountID == "" {
		writeTunnelLifecycleError(
			w,
			managementtunnel.LifecycleErrorInvalidRequest,
			"account ID is required",
			http.StatusBadRequest,
		)
		return "", "", false
	}
	return accountID, userAuth.UserId, true
}

func writeTunnelLifecycleManagerError(
	ctx context.Context,
	w http.ResponseWriter,
	err error,
) {
	httpStatus, message, statusType := tunnelLifecycleSafeError(err)
	entry := log.WithContext(ctx).WithField("http_status", httpStatus)
	if statusType != nil {
		entry = entry.WithField("status_type", *statusType)
	}
	entry.Error("tunnel lifecycle request failed")
	util.WriteErrorResponse(message, httpStatus, w)
}

func tunnelLifecycleSafeError(err error) (int, string, *status.Type) {
	statusErr, ok := status.FromError(err)
	if !ok {
		return http.StatusInternalServerError, "internal server error", nil
	}
	statusType := statusErr.Type()
	switch statusType {
	case status.UserAlreadyExists, status.AlreadyExists:
		return http.StatusConflict, "conflict", &statusType
	case status.PreconditionFailed:
		return http.StatusPreconditionFailed, "precondition failed", &statusType
	case status.PermissionDenied:
		return http.StatusForbidden, "permission denied", &statusType
	case status.NotFound:
		return http.StatusNotFound, "not found", &statusType
	case status.Internal:
		return http.StatusInternalServerError, "internal server error", &statusType
	case status.InvalidArgument:
		return http.StatusUnprocessableEntity, "invalid argument", &statusType
	case status.Unauthorized:
		return http.StatusUnauthorized, "unauthorized", &statusType
	case status.BadRequest:
		return http.StatusBadRequest, "bad request", &statusType
	case status.TooManyRequests:
		return http.StatusTooManyRequests, "too many requests", &statusType
	default:
		return http.StatusInternalServerError, "internal server error", &statusType
	}
}

func decodeTunnelLifecycleRequest(
	w http.ResponseWriter,
	r *http.Request,
	dst *api.TunnelLifecycleRequest,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelLifecycleRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func toTunnelLifecycleRequest(
	request api.TunnelLifecycleRequest,
) (managementtunnel.LifecycleRequest, error) {
	if !request.Action.Valid() {
		return managementtunnel.LifecycleRequest{}, errors.New("unsupported action")
	}
	domain := managementtunnel.LifecycleRequest{
		Action:                  managementtunnel.LifecycleAction(request.Action),
		TargetRevision:          request.TargetRevision,
		ExpectedActiveRevision:  request.ExpectedActiveRevision,
		ExpectedPendingRevision: request.ExpectedPendingRevision,
	}
	if request.ProtocolVersion != nil {
		if !request.ProtocolVersion.Valid() {
			return domain, errors.New("unsupported protocol_version")
		}
		domain.ProtocolVersion = string(*request.ProtocolVersion)
	}
	if request.Policy != nil {
		if !request.Policy.Valid() {
			return domain, errors.New("unsupported policy")
		}
		domain.Policy = types.TunnelAccountPolicy(*request.Policy)
	}
	if err := validateTunnelLifecycleFields(domain); err != nil {
		return domain, err
	}
	return domain, nil
}

func validateTunnelLifecycleFields(
	request managementtunnel.LifecycleRequest,
) error {
	if request.TargetRevision != nil && *request.TargetRevision == 0 {
		return errors.New("target_revision must be greater than zero")
	}
	switch request.Action {
	case managementtunnel.LifecycleActionStage:
		if request.ProtocolVersion == "" || request.Policy != "" ||
			request.TargetRevision != nil {
			return errors.New("stage requires only protocol_version")
		}
	case managementtunnel.LifecycleActionActivate,
		managementtunnel.LifecycleActionRollback:
		if request.TargetRevision == nil || request.ProtocolVersion != "" ||
			request.Policy != "" {
			return errors.New("action requires only target_revision")
		}
	case managementtunnel.LifecycleActionCancelPending:
		if request.ProtocolVersion != "" {
			return errors.New("cancel_pending does not accept protocol_version")
		}
	case managementtunnel.LifecycleActionSetPolicy:
		if request.Policy == "" || request.ProtocolVersion != "" ||
			request.TargetRevision != nil {
			return errors.New("set_policy requires only policy")
		}
	default:
		return errors.New("unsupported action")
	}
	return nil
}

func toAPITunnelLifecycle(
	result *managementtunnel.LifecycleResult,
) api.TunnelLifecycleResponse {
	settings := result.Settings
	policy := settings.TunnelPolicy
	if policy == "" {
		policy = types.TunnelAccountPolicyStandard
	}
	response := api.TunnelLifecycleResponse{
		Policy: api.TunnelLifecycleResponsePolicy(policy),
		Active: toAPITunnelLifecycleProfile(settings.TunnelProfile),
		Pending: toAPITunnelLifecycleProfile(
			settings.TunnelProfilePending,
		),
		Previous: toAPITunnelLifecycleProfile(
			settings.TunnelProfilePrevious,
		),
		Readiness: api.TunnelLifecycleReadiness{
			State: api.TunnelLifecycleReadinessState(
				result.Readiness.State,
			),
			Eligible:        result.Readiness.Eligible,
			Ready:           result.Readiness.Ready,
			Waiting:         result.Readiness.Waiting,
			ExcludedOffline: result.Readiness.ExcludedOffline,
			Incompatible:    result.Readiness.Incompatible,
			PendingRevision: result.Readiness.PendingRevision,
			ObservedAt:      result.Readiness.ObservedAt,
			ErrorCounts:     result.Readiness.ErrorCounts,
		},
	}
	if settings.TunnelProfilePrevious != nil &&
		settings.TunnelProfileGraceUntil.After(result.Readiness.ObservedAt) {
		response.RollbackAvailable = true
		graceUntil := settings.TunnelProfileGraceUntil
		response.RollbackGraceUntil = &graceUntil
	}
	return response
}

func toAPITunnelLifecycleProfile(
	profile *types.TunnelProfile,
) *api.TunnelLifecycleProfile {
	if profile == nil {
		return nil
	}
	return &api.TunnelLifecycleProfile{
		ProtocolVersion: api.TunnelLifecycleProfileProtocolVersion(
			profile.ProtocolVersion,
		),
		Revision:  profile.Revision,
		UpdatedAt: profile.UpdatedAt,
	}
}

func writeTunnelLifecycleError(
	w http.ResponseWriter,
	code managementtunnel.LifecycleErrorCode,
	message string,
	statusCode int,
) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(api.TunnelLifecycleErrorResponse{
		Code:    api.TunnelLifecycleErrorResponseCode(code),
		Message: message,
	}); err != nil {
		log.Errorf("encode tunnel lifecycle error response: %v", err)
	}
}
