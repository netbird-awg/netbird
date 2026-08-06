package middleware

import (
	"net/http"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const passwordChangeRequiredHeader = "X-NetBird-Password-Change-Required" // #nosec G101 -- HTTP response header name, not a credential

// ForcePasswordChangeMiddleware prevents users with an administrator-reset
// password from using the management API until they change it.
type ForcePasswordChangeMiddleware struct {
	store store.Store
}

func NewForcePasswordChangeMiddleware(accountStore store.Store) *ForcePasswordChangeMiddleware {
	return &ForcePasswordChangeMiddleware{store: accountStore}
}

func (m *ForcePasswordChangeMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		if err != nil {
			// Authentication bypass routes implement their own access control and
			// deliberately reach this middleware without a user in the context.
			next.ServeHTTP(w, r)
			return
		}

		user, err := m.store.GetUserByUserID(r.Context(), store.LockingStrengthNone, userAuth.UserId)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.Internal, "failed to validate password change requirements"), w)
			return
		}

		if !user.ForcePasswordChange || isPasswordChangeRecoveryRequest(r, userAuth.UserId) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set(passwordChangeRequiredHeader, "true")
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "password change required"), w)
	})
}

func isPasswordChangeRecoveryRequest(r *http.Request, userID string) bool {
	if r.Method == http.MethodGet && r.URL.Path == "/api/users/current" {
		return true
	}

	targetUserID := mux.Vars(r)["userId"]
	if targetUserID == "" || targetUserID != userID {
		return false
	}

	if r.Method == http.MethodPut && r.URL.Path == "/api/users/"+targetUserID+"/password" {
		return true
	}
	return false
}
