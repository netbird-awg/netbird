package users

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxSensitiveJSONBodyBytes = 64 * 1024

// decodeStrictJSONBody bounds sensitive request bodies and accepts exactly one
// JSON object. This avoids unbounded allocations and ambiguous trailing input
// on password- and credential-bearing endpoints.
func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSensitiveJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
