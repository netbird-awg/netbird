package idp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxIdentityProviderJSONBodyBytes = 256 * 1024

// decodeStrictJSONBody bounds credential and certificate-bearing requests,
// rejects unknown fields, and accepts exactly one JSON object.
func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxIdentityProviderJSONBodyBytes)
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
