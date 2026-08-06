package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func requestWithUserAuth(method, path string, userAuth auth.UserAuth) *http.Request {
	return nbcontext.SetUserAuthInRequest(httptest.NewRequest(method, path, nil), userAuth)
}

func TestForcePasswordChangeMiddlewareBlocksPAT(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountStore := store.NewMockStore(ctrl)
	accountStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").Return(&types.User{
		Id:                  "user-1",
		ForcePasswordChange: true,
	}, nil)

	nextCalled := false
	handler := NewForcePasswordChangeMiddleware(accountStore).Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestWithUserAuth(http.MethodGet, "/api/peers", auth.UserAuth{UserId: "user-1", IsPAT: true}))

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Equal(t, "true", recorder.Header().Get(passwordChangeRequiredHeader))
	assert.False(t, nextCalled)
}

func TestForcePasswordChangeMiddlewareAllowsAuthenticationBypassRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountStore := store.NewMockStore(ctrl)
	handler := NewForcePasswordChangeMiddleware(accountStore).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/integrations/webhook", nil))

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestForcePasswordChangeMiddlewareBlocksJWT(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountStore := store.NewMockStore(ctrl)
	accountStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").Return(&types.User{
		Id:                  "user-1",
		ForcePasswordChange: true,
	}, nil)
	handler := NewForcePasswordChangeMiddleware(accountStore).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := requestWithUserAuth(http.MethodGet, "/api/peers", auth.UserAuth{UserId: "user-1"})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestForcePasswordChangeMiddlewareAllowsUserWithoutForcedChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountStore := store.NewMockStore(ctrl)
	accountStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").Return(&types.User{Id: "user-1"}, nil)
	handler := NewForcePasswordChangeMiddleware(accountStore).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := requestWithUserAuth(http.MethodGet, "/api/peers", auth.UserAuth{UserId: "user-1"})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
}

func TestForcePasswordChangeMiddlewareAllowsSelfRecoveryEndpoints(t *testing.T) {
	allowed := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/users/current"},
		{method: http.MethodPut, path: "/api/users/user-1/password"},
	}

	for _, testCase := range allowed {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			accountStore := store.NewMockStore(ctrl)
			accountStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").Return(&types.User{
				Id:                  "user-1",
				ForcePasswordChange: true,
			}, nil)
			router := mux.NewRouter()
			router.Use(NewForcePasswordChangeMiddleware(accountStore).Handler)
			router.HandleFunc("/api/users/current", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			router.HandleFunc("/api/users/{userId}/password", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

			req := requestWithUserAuth(testCase.method, testCase.path, auth.UserAuth{UserId: "user-1"})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			assert.Equal(t, http.StatusNoContent, recorder.Code)
		})
	}
}

func TestForcePasswordChangeMiddlewareRejectsOtherUserPasswordEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountStore := store.NewMockStore(ctrl)
	accountStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, "user-1").Return(&types.User{
		Id:                  "user-1",
		ForcePasswordChange: true,
	}, nil)
	router := mux.NewRouter()
	router.Use(NewForcePasswordChangeMiddleware(accountStore).Handler)
	router.HandleFunc("/api/users/{userId}/password", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	req := requestWithUserAuth(http.MethodPut, "/api/users/user-2/password", auth.UserAuth{UserId: "user-1"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
}
