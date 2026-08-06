package eventstreaming

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/netbirdio/netbird/management/server/outbound"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	maskedSecret       = "********"
	maxURLLength       = 2048
	maxHeadersLength   = 16 << 10
	maxTemplateLength  = 64 << 10
	maxConfigValueSize = 128 << 10
	maxHeaderCount     = 64
)

var (
	supportedPlatforms = []string{"datadog", "s3", "firehose", "generic_http"}
	awsRegionPattern   = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d$`)
	bucketPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	headerNamePattern  = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)
	sensitiveKey       = regexp.MustCompile(`(?i)(authorization|api[-_]?key|secret|token|password|credential|cookie)`)
)

func normalizeConfig(
	ctx context.Context,
	validator *outbound.Validator,
	platform string,
	input, previous map[string]string,
) (map[string]string, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if !slices.Contains(supportedPlatforms, platform) {
		return nil, status.Errorf(status.InvalidArgument, "unsupported event streaming platform")
	}
	config := make(map[string]string, len(input))
	for key, value := range input {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || len(value) > maxConfigValueSize {
			return nil, status.Errorf(status.InvalidArgument, "invalid event streaming configuration")
		}
		value = strings.TrimSpace(value)
		if isMasked(value) && sensitiveKey.MatchString(key) {
			value = previous[key]
		}
		config[key] = value
	}

	var allowed, required []string
	switch platform {
	case "datadog":
		allowed = []string{"api_key", "api_url"}
		required = allowed
	case "s3":
		allowed = []string{"access_key", "secret_key", "bucket_name", "region"}
		required = allowed
	case "firehose":
		allowed = []string{"access_key", "secret_key", "stream_name", "region"}
		required = allowed
	case "generic_http":
		allowed = []string{"url", "headers", "body_template"}
		required = []string{"url"}
	}
	for key := range config {
		if !slices.Contains(allowed, key) {
			return nil, status.Errorf(status.InvalidArgument, "unsupported %s configuration field", platform)
		}
	}
	for _, key := range required {
		if strings.TrimSpace(config[key]) == "" {
			return nil, status.Errorf(status.InvalidArgument, "%s is required", key)
		}
	}

	switch platform {
	case "datadog":
		if len(config["api_key"]) > 512 {
			return nil, status.Errorf(status.InvalidArgument, "Datadog API key is too long")
		}
		if err := validateDatadogURL(ctx, validator, config["api_url"]); err != nil {
			return nil, err
		}
	case "s3":
		if err := validateAWSConfig(config); err != nil {
			return nil, err
		}
		if !bucketPattern.MatchString(config["bucket_name"]) ||
			strings.Contains(config["bucket_name"], "..") ||
			isIPv4Like(config["bucket_name"]) {
			return nil, status.Errorf(status.InvalidArgument, "invalid S3 bucket name")
		}
	case "firehose":
		if err := validateAWSConfig(config); err != nil {
			return nil, err
		}
		if len(config["stream_name"]) > 64 || strings.ContainsAny(config["stream_name"], "\r\n") {
			return nil, status.Errorf(status.InvalidArgument, "invalid Firehose stream name")
		}
	case "generic_http":
		if err := validateGenericHTTPConfig(ctx, validator, config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func validateDatadogURL(ctx context.Context, validator *outbound.Validator, raw string) error {
	target, err := parseOutboundURL(raw)
	if err != nil {
		return err
	}
	allowedHosts := []string{
		"http-intake.logs.datadoghq.eu",
		"http-intake.logs.datadoghq.com",
		"http-intake.logs.us3.datadoghq.com",
		"http-intake.logs.us5.datadoghq.com",
		"http-intake.logs.ddog-gov.com",
		"http-intake.logs.ap1.datadoghq.com",
	}
	if !slices.Contains(allowedHosts, strings.ToLower(target.Hostname())) ||
		target.Path != "/api/v2/logs" ||
		target.RawQuery != "" ||
		target.Fragment != "" {
		return status.Errorf(status.InvalidArgument, "unsupported Datadog intake URL")
	}
	if _, err := validator.ValidateURL(ctx, target); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid Datadog destination: %v", err)
	}
	return nil
}

func validateGenericHTTPConfig(
	ctx context.Context,
	validator *outbound.Validator,
	config map[string]string,
) error {
	target, err := parseOutboundURL(config["url"])
	if err != nil {
		return err
	}
	if _, err := validator.ValidateURL(ctx, target); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid HTTP destination: %v", err)
	}
	headers, err := parseHeaders(config["headers"])
	if err != nil {
		return status.Errorf(status.InvalidArgument, "%v", err)
	}
	if len(headers) > maxHeaderCount {
		return status.Errorf(status.InvalidArgument, "too many HTTP headers")
	}
	for name, value := range headers {
		if !headerNamePattern.MatchString(name) || strings.ContainsAny(value, "\r\n") {
			return status.Errorf(status.InvalidArgument, "invalid HTTP header")
		}
		canonical := http.CanonicalHeaderKey(name)
		switch canonical {
		case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Trailer":
			return status.Errorf(status.InvalidArgument, "HTTP header %s is managed by the server", canonical)
		}
		if strings.HasPrefix(canonical, "Proxy-") {
			return status.Errorf(status.InvalidArgument, "proxy HTTP headers are not allowed")
		}
	}
	if body := config["body_template"]; body != "" {
		if len(body) > maxTemplateLength {
			return status.Errorf(status.InvalidArgument, "HTTP body template is too large")
		}
		if _, err := template.New("event").Option("missingkey=error").Parse(body); err != nil {
			return status.Errorf(status.InvalidArgument, "invalid HTTP body template")
		}
	}
	return nil
}

func validateAWSConfig(config map[string]string) error {
	if len(config["access_key"]) > 256 || len(config["secret_key"]) > 512 {
		return status.Errorf(status.InvalidArgument, "invalid AWS credentials")
	}
	if !awsRegionPattern.MatchString(config["region"]) {
		return status.Errorf(status.InvalidArgument, "invalid AWS region")
	}
	return nil
}

func parseOutboundURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURLLength {
		return nil, status.Errorf(status.InvalidArgument, "invalid outbound URL")
	}
	target, err := url.ParseRequestURI(raw)
	if err != nil || target.Host == "" {
		return nil, status.Errorf(status.InvalidArgument, "invalid outbound URL")
	}
	return target, nil
}

func parseHeaders(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	if len(raw) > maxHeadersLength {
		return nil, fmt.Errorf("HTTP headers are too large")
	}
	var headers map[string]string
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&headers); err != nil || headers == nil {
		return nil, fmt.Errorf("HTTP headers must be a JSON string map")
	}
	return headers, nil
}

func mergeMaskedHeaders(currentRaw, requestedRaw string) (string, error) {
	requested, err := parseHeaders(requestedRaw)
	if err != nil {
		return "", err
	}
	current, err := parseHeaders(currentRaw)
	if err != nil {
		return "", err
	}
	for name, value := range requested {
		if !isMasked(value) {
			continue
		}
		for currentName, currentValue := range current {
			if strings.EqualFold(name, currentName) {
				requested[name] = currentValue
				break
			}
		}
	}
	data, err := json.Marshal(requested)
	if err != nil {
		return "", fmt.Errorf("encode HTTP headers: %w", err)
	}
	return string(data), nil
}

func maskConfig(config map[string]string) map[string]string {
	masked := make(map[string]string, len(config))
	for key, value := range config {
		if key == "headers" {
			headers, err := parseHeaders(value)
			if err != nil {
				masked[key] = "{}"
				continue
			}
			for name := range headers {
				if sensitiveKey.MatchString(name) {
					headers[name] = maskedSecret
				}
			}
			data, _ := json.Marshal(headers)
			masked[key] = string(data)
			continue
		}
		if sensitiveKey.MatchString(key) {
			masked[key] = maskedSecret
			continue
		}
		masked[key] = value
	}
	return masked
}

func isMasked(value string) bool {
	trimmed := strings.TrimSpace(value)
	return len(trimmed) >= 4 && strings.Trim(trimmed, "*") == ""
}

func isIPv4Like(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
