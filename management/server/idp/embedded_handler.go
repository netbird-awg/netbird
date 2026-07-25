package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (m *EmbeddedIdPManager) handlerWithLogoutDiscovery() http.Handler {
	dexHandler := m.provider.Handler()
	issuer := m.provider.GetIssuer()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth2/end-session", func(w http.ResponseWriter, r *http.Request) {
		logoutRequest := r.Clone(r.Context())
		logoutURL := *r.URL
		logoutURL.Path = "/oauth2/logout"
		logoutRequest.URL = &logoutURL
		dexHandler.ServeHTTP(w, logoutRequest)
	})

	mux.HandleFunc("/oauth2/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		recorder := &oidcResponseRecorder{body: &strings.Builder{}, header: http.Header{}, statusCode: http.StatusOK}
		dexHandler.ServeHTTP(recorder, r)
		copyHTTPHeaders(w.Header(), recorder.header)

		var document map[string]interface{}
		if err := json.Unmarshal([]byte(recorder.body.String()), &document); err != nil {
			w.WriteHeader(recorder.statusCode)
			_, _ = w.Write([]byte(recorder.body.String()))
			return
		}
		document["end_session_endpoint"] = issuer + "/end-session"

		body, err := json.Marshal(document)
		if err != nil {
			http.Error(w, "failed to encode discovery document", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(recorder.statusCode)
		_, _ = w.Write(body)
	})

	mux.Handle("/oauth2/", dexHandler)
	return mux
}

func copyHTTPHeaders(dst, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

type oidcResponseRecorder struct {
	header     http.Header
	body       *strings.Builder
	statusCode int
}

func (r *oidcResponseRecorder) Header() http.Header         { return r.header }
func (r *oidcResponseRecorder) WriteHeader(code int)        { r.statusCode = code }
func (r *oidcResponseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
