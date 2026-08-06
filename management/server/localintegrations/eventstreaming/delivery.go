package eventstreaming

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
)

const maxRenderedBody = 1 << 20

var credentialErrorPattern = regexp.MustCompile(
	`(?i)(authorization|api[-_ ]?key|secret|token|password|credential)(\s*[:=]\s*)([^\s,;]+)`,
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type deliveryFailure struct {
	message   string
	retryable bool
}

func (e *deliveryFailure) Error() string { return e.message }

func permanentDeliveryError(message string) error {
	return &deliveryFailure{message: message, retryable: false}
}

func retryableDeliveryError(message string) error {
	return &deliveryFailure{message: message, retryable: true}
}

func isRetryable(err error) bool {
	var failure *deliveryFailure
	if errors.As(err, &failure) {
		return failure.retryable
	}
	return true
}

func sanitizeDeliveryError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 {
			return ' '
		}
		return r
	}, err.Error())
	message = credentialErrorPattern.ReplaceAllString(message, "$1$2[redacted]")
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func (s *Service) deliver(
	ctx context.Context,
	integration *eventmodel.Integration,
	config map[string]string,
	event StreamEvent,
	rawPayload []byte,
) error {
	switch integration.Platform {
	case "generic_http":
		body, err := renderGenericBody(config["body_template"], event, rawPayload)
		if err != nil {
			return permanentDeliveryError("invalid Generic HTTP body template output")
		}
		headers, err := parseHeaders(config["headers"])
		if err != nil {
			return permanentDeliveryError("invalid stored Generic HTTP headers")
		}
		return s.postJSON(ctx, config["url"], headers, body)
	case "datadog":
		body, err := json.Marshal([]map[string]any{{
			"ddsource":     "netbird",
			"service":      "netbird-management",
			"id":           event.ID,
			"timestamp":    event.Timestamp,
			"message":      event.Message,
			"event_code":   event.Code,
			"initiator_id": event.InitiatorID,
			"target_id":    event.TargetID,
			"account_id":   event.AccountID,
			"meta":         event.Meta,
		}})
		if err != nil {
			return permanentDeliveryError("failed to encode Datadog payload")
		}
		return s.postJSON(ctx, config["api_url"], map[string]string{
			"DD-API-KEY": config["api_key"],
		}, body)
	case "s3":
		return s.putS3(ctx, config, event, rawPayload)
	case "firehose":
		return s.putFirehose(ctx, config, rawPayload)
	default:
		return permanentDeliveryError("unsupported event streaming platform")
	}
}

func (s *Service) postJSON(
	ctx context.Context,
	rawURL string,
	headers map[string]string,
	body []byte,
) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return permanentDeliveryError("invalid stored HTTP destination")
	}
	if _, err := s.validator.ValidateURL(ctx, target); err != nil {
		return permanentDeliveryError("HTTP destination is no longer allowed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return permanentDeliveryError("failed to build HTTP request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "NetBird-Local-Event-Streaming/1")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return retryableDeliveryError("event streaming HTTP request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	message := fmt.Sprintf("event streaming destination returned HTTP %d", response.StatusCode)
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return retryableDeliveryError(message)
	}
	return permanentDeliveryError(message)
}

func (s *Service) awsConfig(ctx context.Context, config map[string]string) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(config["region"]),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			config["access_key"], config["secret_key"], "",
		)),
	)
	if err != nil {
		return aws.Config{}, err
	}
	cfg.HTTPClient = s.httpClient
	return cfg, nil
}

func (s *Service) putS3(
	ctx context.Context,
	config map[string]string,
	event StreamEvent,
	payload []byte,
) error {
	cfg, err := s.awsConfig(ctx, config)
	if err != nil {
		return permanentDeliveryError("invalid AWS configuration")
	}
	client := s3.NewFromConfig(cfg)
	key := fmt.Sprintf(
		"netbird-events/%s/%s/%020d-%d.json",
		safeObjectSegment(event.AccountID),
		event.Timestamp.UTC().Format("2006/01/02"),
		event.Timestamp.UnixNano(),
		event.ID,
	)
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(config["bucket_name"]),
		Key:         aws.String(key),
		Body:        bytes.NewReader(payload),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return retryableDeliveryError("Amazon S3 delivery failed")
	}
	return nil
}

func (s *Service) putFirehose(
	ctx context.Context,
	config map[string]string,
	payload []byte,
) error {
	cfg, err := s.awsConfig(ctx, config)
	if err != nil {
		return permanentDeliveryError("invalid AWS configuration")
	}
	client := firehose.NewFromConfig(cfg)
	data := append(append([]byte(nil), payload...), '\n')
	_, err = client.PutRecord(ctx, &firehose.PutRecordInput{
		DeliveryStreamName: aws.String(config["stream_name"]),
		Record:             &firehosetypes.Record{Data: data},
	})
	if err != nil {
		return retryableDeliveryError("Amazon Data Firehose delivery failed")
	}
	return nil
}

func renderGenericBody(bodyTemplate string, event StreamEvent, rawPayload []byte) ([]byte, error) {
	if strings.TrimSpace(bodyTemplate) == "" {
		return rawPayload, nil
	}
	meta, err := json.Marshal(event.Meta)
	if err != nil {
		return nil, err
	}
	data := struct {
		ID          uint64
		Timestamp   time.Time
		Code        string
		Message     string
		InitiatorID string
		TargetID    string
		AccountID   string
		Meta        string
	}{
		ID:          event.ID,
		Timestamp:   event.Timestamp,
		Code:        escapeJSONString(event.Code),
		Message:     escapeJSONString(event.Message),
		InitiatorID: escapeJSONString(event.InitiatorID),
		TargetID:    escapeJSONString(event.TargetID),
		AccountID:   escapeJSONString(event.AccountID),
		Meta:        escapeJSONString(string(meta)),
	}
	parsed, err := template.New("event").Option("missingkey=error").Parse(bodyTemplate)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err := parsed.Execute(&body, data); err != nil {
		return nil, err
	}
	if body.Len() > maxRenderedBody || !json.Valid(body.Bytes()) {
		return nil, fmt.Errorf("rendered body must be valid JSON smaller than %d bytes", maxRenderedBody)
	}
	return body.Bytes(), nil
}

func escapeJSONString(value string) string {
	encoded, _ := json.Marshal(value)
	if len(encoded) < 2 {
		return ""
	}
	return string(encoded[1 : len(encoded)-1])
}

func safeObjectSegment(value string) string {
	var result strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' {
			result.WriteRune(r)
		}
	}
	if result.Len() == 0 {
		return "unknown"
	}
	return result.String()
}
