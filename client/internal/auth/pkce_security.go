package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func setPKCEBrowserSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src data:; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func validateLoopbackRedirectURL(redirectURL string) error {
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		return fmt.Errorf("parse redirect URL: %w", err)
	}
	if parsedURL.Scheme != "http" {
		return fmt.Errorf("redirect scheme must be http")
	}
	if parsedURL.Port() == "" {
		return fmt.Errorf("redirect URL must include a port")
	}
	host := parsedURL.Hostname()
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("redirect host must be loopback")
		}
	}
	return nil
}
