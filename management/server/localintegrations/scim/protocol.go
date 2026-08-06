package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	scimlib "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	scimschema "github.com/elimity-com/scim/schema"
	"github.com/gorilla/mux"
	"github.com/rs/xid"
	filter "github.com/scim2/filter-parser/v2"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
)

const (
	maxSCIMRequestBody  = 1 << 20
	maxSCIMResults      = 200
	scimRateLimit       = 600
	scimRateLimitWindow = time.Minute
)

type integrationContextKey struct{}

// RegisterProtocolEndpoints mounts the bearer-authenticated SCIM v2 protocol
// endpoint. These routes bypass NetBird JWT authentication because they
// authenticate with their own high-entropy provisioning token.
func RegisterProtocolEndpoints(service *Service, router *mux.Router) error {
	for _, pattern := range []string{
		"/api/scim/v2",
		"/api/scim/v2/*",
		"/api/scim/v2/*/*",
	} {
		if err := bypass.AddBypassPath(pattern); err != nil {
			return fmt.Errorf("register SCIM authentication bypass: %w", err)
		}
	}
	handler := &protocolHandler{
		service: service,
		server: scimlib.Server{
			Config: scimlib.ServiceProviderConfig{
				MaxResults:       maxSCIMResults,
				SupportFiltering: true,
				SupportPatch:     true,
				AuthenticationSchemes: []scimlib.AuthenticationScheme{
					{
						Type:        scimlib.AuthenticationTypeOauthBearerToken,
						Name:        "Bearer Token",
						Description: "NetBird SCIM provisioning token",
						Primary:     true,
					},
				},
			},
			ResourceTypes: []scimlib.ResourceType{
				{
					ID:          optional.NewString("User"),
					Name:        "User",
					Endpoint:    "/Users",
					Description: optional.NewString("User Account"),
					Schema:      scimschema.CoreUserSchema(),
					SchemaExtensions: []scimlib.SchemaExtension{
						{Schema: scimschema.ExtensionEnterpriseUser()},
					},
					Handler: &resourceHandler{service: service, resourceType: scimmodel.ResourceTypeUser},
				},
				{
					ID:          optional.NewString("Group"),
					Name:        "Group",
					Endpoint:    "/Groups",
					Description: optional.NewString("Group"),
					Schema:      scimschema.CoreGroupSchema(),
					Handler:     &resourceHandler{service: service, resourceType: scimmodel.ResourceTypeGroup},
				},
			},
		},
	}
	router.PathPrefix("/scim/v2").Handler(handler)
	return nil
}

type protocolHandler struct {
	service *Service
	server  scimlib.Server
}

func (h *protocolHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !h.service.allowProtocolRequest("source:"+remoteHost(r.RemoteAddr), time.Now().UTC()) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "SCIM request rate limit exceeded")
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		writeProtocolError(w, http.StatusUnauthorized, "invalid or missing bearer token")
		return
	}
	integration, err := h.service.store.GetSCIMIntegrationByTokenHash(r.Context(), tokenDigest(token))
	if err != nil || integration == nil || !integration.Enabled {
		writeProtocolError(w, http.StatusUnauthorized, "invalid or disabled bearer token")
		return
	}
	rateKey := fmt.Sprintf("integration:%d", integration.ID)
	if !h.service.allowProtocolRequest(rateKey, time.Now().UTC()) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "SCIM request rate limit exceeded")
		return
	}
	if r.ContentLength > maxSCIMRequestBody {
		writeProtocolError(w, http.StatusRequestEntityTooLarge, "SCIM request body is too large")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSCIMRequestBody)
	ctx := context.WithValue(r.Context(), integrationContextKey{}, integration)
	cloned := r.Clone(ctx)
	cloned.URL.Path = "/v2" + strings.TrimPrefix(r.URL.Path, "/api/scim/v2")
	h.server.ServeHTTP(w, cloned)
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, strings.HasPrefix(token, tokenPrefix) && len(token) <= 128
}

func writeProtocolError(w http.ResponseWriter, statusCode int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	if statusCode == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  fmt.Sprint(statusCode),
		"detail":  detail,
	})
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func (s *Service) allowProtocolRequest(key string, now time.Time) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	cutoff := now.Add(-scimRateLimitWindow)
	if len(s.rateCalls) > 4096 {
		for existingKey, existingCalls := range s.rateCalls {
			if len(existingCalls) == 0 || existingCalls[len(existingCalls)-1].Before(cutoff) {
				delete(s.rateCalls, existingKey)
			}
		}
		if _, exists := s.rateCalls[key]; !exists && len(s.rateCalls) > 8192 {
			return false
		}
	}
	calls := s.rateCalls[key]
	index := 0
	for index < len(calls) && calls[index].Before(cutoff) {
		index++
	}
	calls = append(calls[index:], now)
	if len(calls) > scimRateLimit {
		s.rateCalls[key] = calls
		return false
	}
	s.rateCalls[key] = calls
	return true
}

func integrationFromRequest(r *http.Request) (*scimmodel.Integration, error) {
	integration, ok := r.Context().Value(integrationContextKey{}).(*scimmodel.Integration)
	if !ok || integration == nil {
		return nil, scimerrors.ScimError{Status: http.StatusUnauthorized}
	}
	return integration, nil
}

type resourceHandler struct {
	service      *Service
	resourceType string
}

func (h *resourceHandler) Create(r *http.Request, attributes scimlib.ResourceAttributes) (scimlib.Resource, error) {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return scimlib.Resource{}, err
	}
	if err := h.ensureUnique(r.Context(), integration.ID, "", attributes); err != nil {
		return scimlib.Resource{}, err
	}
	now := time.Now().UTC()
	resource, err := h.reusableDeletedResource(r.Context(), integration.ID, attributes)
	if err != nil {
		return scimlib.Resource{}, err
	}
	if resource == nil {
		resource = &scimmodel.Resource{
			ID:            xid.New().String(),
			IntegrationID: integration.ID,
			ResourceType:  h.resourceType,
			CreatedAt:     now,
		}
	}
	if err := h.save(r.Context(), resource, attributes, now); err != nil {
		return scimlib.Resource{}, err
	}
	h.service.wakeWorker()
	return resourceResponse(resource, attributes), nil
}

//nolint:nilnil // A nil resource means no deleted SCIM identity can be reused.
func (h *resourceHandler) reusableDeletedResource(
	ctx context.Context,
	integrationID uint64,
	attributes scimlib.ResourceAttributes,
) (*scimmodel.Resource, error) {
	externalHash := keyedLookup(h.service.lookupKey, attributeString(attributes, "externalId"))
	userNameHash := keyedLookup(h.service.lookupKey, attributeString(attributes, "userName"))
	if externalHash == "" && userNameHash == "" {
		return nil, nil
	}
	resources, err := h.service.store.ListSCIMResources(ctx, integrationID, h.resourceType, true)
	if err != nil {
		return nil, internalSCIMError(ctx, err)
	}
	for _, resource := range resources {
		if !resource.Deleted {
			continue
		}
		if externalHash != "" && resource.ExternalIDHash == externalHash {
			return resource, nil
		}
		if h.resourceType == scimmodel.ResourceTypeUser &&
			userNameHash != "" && resource.UserNameHash == userNameHash {
			return resource, nil
		}
	}
	return nil, nil
}

func (h *resourceHandler) Get(r *http.Request, id string) (scimlib.Resource, error) {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return scimlib.Resource{}, err
	}
	resource, err := h.service.store.GetSCIMResource(r.Context(), integration.ID, h.resourceType, id)
	if err != nil {
		if isNotFound(err) {
			return scimlib.Resource{}, scimerrors.ScimErrorResourceNotFound(id)
		}
		return scimlib.Resource{}, internalSCIMError(r.Context(), err)
	}
	attributes, err := h.service.decryptResource(resource)
	if err != nil {
		return scimlib.Resource{}, internalSCIMError(r.Context(), err)
	}
	return resourceResponse(resource, attributes), nil
}

func (h *resourceHandler) GetAll(r *http.Request, params scimlib.ListRequestParams) (scimlib.Page, error) {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return scimlib.Page{}, err
	}
	resources, err := h.listFiltered(r.Context(), integration.ID, params.Filter)
	if err != nil {
		return scimlib.Page{}, err
	}
	total := len(resources)
	if params.Count <= 0 {
		return scimlib.Page{TotalResults: total, Resources: []scimlib.Resource{}}, nil
	}
	start := max(params.StartIndex-1, 0)
	if start > total {
		start = total
	}
	end := min(start+params.Count, total)
	return scimlib.Page{TotalResults: total, Resources: resources[start:end]}, nil
}

func (h *resourceHandler) Replace(r *http.Request, id string, attributes scimlib.ResourceAttributes) (scimlib.Resource, error) {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return scimlib.Resource{}, err
	}
	resource, err := h.service.store.GetSCIMResource(r.Context(), integration.ID, h.resourceType, id)
	if err != nil {
		if isNotFound(err) {
			return scimlib.Resource{}, scimerrors.ScimErrorResourceNotFound(id)
		}
		return scimlib.Resource{}, internalSCIMError(r.Context(), err)
	}
	if err := h.ensureUnique(r.Context(), integration.ID, id, attributes); err != nil {
		return scimlib.Resource{}, err
	}
	if err := h.save(r.Context(), resource, attributes, time.Now().UTC()); err != nil {
		return scimlib.Resource{}, err
	}
	h.service.wakeWorker()
	return resourceResponse(resource, attributes), nil
}

func (h *resourceHandler) Delete(r *http.Request, id string) error {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return err
	}
	if err := h.service.store.DeleteSCIMResourceAndQueue(
		r.Context(), integration.ID, h.resourceType, id, time.Now().UTC(),
	); err != nil {
		if isNotFound(err) {
			return scimerrors.ScimErrorResourceNotFound(id)
		}
		return internalSCIMError(r.Context(), err)
	}
	h.service.wakeWorker()
	return nil
}

func (h *resourceHandler) Patch(
	r *http.Request,
	id string,
	operations []scimlib.PatchOperation,
) (scimlib.Resource, error) {
	integration, err := integrationFromRequest(r)
	if err != nil {
		return scimlib.Resource{}, err
	}
	resource, err := h.service.store.GetSCIMResource(r.Context(), integration.ID, h.resourceType, id)
	if err != nil {
		if isNotFound(err) {
			return scimlib.Resource{}, scimerrors.ScimErrorResourceNotFound(id)
		}
		return scimlib.Resource{}, internalSCIMError(r.Context(), err)
	}
	attributes, err := h.service.decryptResource(resource)
	if err != nil {
		return scimlib.Resource{}, internalSCIMError(r.Context(), err)
	}
	if err := applyPatchOperations(attributes, operations); err != nil {
		return scimlib.Resource{}, err
	}
	if err := h.ensureUnique(r.Context(), integration.ID, id, attributes); err != nil {
		return scimlib.Resource{}, err
	}
	if err := h.save(r.Context(), resource, attributes, time.Now().UTC()); err != nil {
		return scimlib.Resource{}, err
	}
	h.service.wakeWorker()
	return resourceResponse(resource, attributes), nil
}

func (h *resourceHandler) save(
	ctx context.Context,
	resource *scimmodel.Resource,
	attributes scimlib.ResourceAttributes,
	now time.Time,
) error {
	payload, err := json.Marshal(attributes)
	if err != nil {
		return internalSCIMError(ctx, err)
	}
	encrypted, err := h.service.encryptor.Encrypt(string(payload))
	if err != nil {
		return internalSCIMError(ctx, err)
	}
	resource.ExternalIDHash = keyedLookup(h.service.lookupKey, attributeString(attributes, "externalId"))
	resource.UserNameHash = keyedLookup(h.service.lookupKey, attributeString(attributes, "userName"))
	resource.EncryptedPayload = encrypted
	resource.SourceFingerprint = fingerprint(payload)
	resource.Deleted = false
	resource.UpdatedAt = now
	if err := h.service.store.SaveSCIMResourceAndQueue(ctx, resource, now); err != nil {
		return internalSCIMError(ctx, err)
	}
	return nil
}

func (h *resourceHandler) ensureUnique(
	ctx context.Context,
	integrationID uint64,
	currentID string,
	attributes scimlib.ResourceAttributes,
) error {
	for column, value := range map[string]string{
		"external_id_hash": attributeString(attributes, "externalId"),
		"user_name_hash":   attributeString(attributes, "userName"),
	} {
		if value == "" || (h.resourceType == scimmodel.ResourceTypeGroup && column == "user_name_hash") {
			continue
		}
		resources, err := h.service.store.FindSCIMResources(
			ctx, integrationID, h.resourceType, column, keyedLookup(h.service.lookupKey, value),
		)
		if err != nil {
			return internalSCIMError(ctx, err)
		}
		for _, resource := range resources {
			if resource.ID != currentID {
				return scimerrors.ScimErrorUniqueness
			}
		}
	}
	return nil
}

func (h *resourceHandler) listFiltered(
	ctx context.Context,
	integrationID uint64,
	expression filter.Expression,
) ([]scimlib.Resource, error) {
	var resources []*scimmodel.Resource
	var err error
	if expression == nil {
		resources, err = h.service.store.ListSCIMResources(ctx, integrationID, h.resourceType, false)
	} else {
		attributeExpression, ok := expression.(*filter.AttributeExpression)
		if !ok || attributeExpression.Operator != filter.EQ {
			return nil, scimerrors.ScimErrorInvalidFilter
		}
		value, ok := attributeExpression.CompareValue.(string)
		if !ok {
			return nil, scimerrors.ScimErrorInvalidFilter
		}
		var column string
		switch strings.ToLower(attributeExpression.AttributePath.AttributeName) {
		case "externalid":
			column = "external_id_hash"
		case "username":
			column = "user_name_hash"
		default:
			return nil, scimerrors.ScimErrorInvalidFilter
		}
		resources, err = h.service.store.FindSCIMResources(
			ctx, integrationID, h.resourceType, column, keyedLookup(h.service.lookupKey, value),
		)
	}
	if err != nil {
		return nil, internalSCIMError(ctx, err)
	}
	result := make([]scimlib.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource.Deleted {
			continue
		}
		attributes, err := h.service.decryptResource(resource)
		if err != nil {
			return nil, internalSCIMError(ctx, err)
		}
		result = append(result, resourceResponse(resource, attributes))
	}
	return result, nil
}

func (s *Service) decryptResource(resource *scimmodel.Resource) (scimlib.ResourceAttributes, error) {
	plain, err := s.encryptor.Decrypt(resource.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypt SCIM resource: %w", err)
	}
	var attributes scimlib.ResourceAttributes
	if err := json.Unmarshal([]byte(plain), &attributes); err != nil {
		return nil, fmt.Errorf("decode SCIM resource: %w", err)
	}
	return attributes, nil
}

func resourceResponse(resource *scimmodel.Resource, attributes scimlib.ResourceAttributes) scimlib.Resource {
	var externalID optional.String
	if value := attributeString(attributes, "externalId"); value != "" {
		externalID = optional.NewString(value)
	}
	return scimlib.Resource{
		ID:         resource.ID,
		ExternalID: externalID,
		Attributes: attributes,
		Meta: scimlib.Meta{
			Created:      &resource.CreatedAt,
			LastModified: &resource.UpdatedAt,
			Version:      `W/"` + resource.SourceFingerprint + `"`,
		},
	}
}

func attributeString(attributes scimlib.ResourceAttributes, name string) string {
	value, ok := attributes[name]
	if !ok || value == nil {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func internalSCIMError(ctx context.Context, err error) error {
	log.WithContext(ctx).WithError(err).Error("local SCIM request failed")
	return scimerrors.ScimErrorInternal
}

func applyPatchOperations(attributes scimlib.ResourceAttributes, operations []scimlib.PatchOperation) error {
	for _, operation := range operations {
		op := strings.ToLower(operation.Op)
		if operation.Path == nil {
			if op == scimlib.PatchOperationRemove {
				return scimerrors.ScimErrorInvalidPath
			}
			values, ok := stringMap(operation.Value)
			if !ok {
				return scimerrors.ScimErrorInvalidValue
			}
			for key, value := range values {
				attributes[key] = value
			}
			continue
		}

		path := operation.Path
		if path.SubAttribute != nil {
			return scimerrors.ScimErrorInvalidPath
		}
		name := path.AttributePath.AttributeName
		if path.ValueExpression != nil {
			if strings.ToLower(name) != "members" || op != scimlib.PatchOperationRemove {
				return scimerrors.ScimErrorInvalidPath
			}
			value, ok := equalityFilterValue(path.ValueExpression, "value")
			if !ok {
				return scimerrors.ScimErrorInvalidPath
			}
			attributes[name] = removeComplexValue(attributes[name], value)
			continue
		}

		switch op {
		case scimlib.PatchOperationRemove:
			delete(attributes, name)
		case scimlib.PatchOperationReplace:
			attributes[name] = operation.Value
		case scimlib.PatchOperationAdd:
			if strings.EqualFold(name, "members") {
				attributes[name] = appendComplexValues(attributes[name], operation.Value)
			} else {
				attributes[name] = operation.Value
			}
		default:
			return scimerrors.ScimErrorInvalidValue
		}
	}
	return nil
}

func equalityFilterValue(expression filter.Expression, attribute string) (string, bool) {
	comparison, ok := expression.(*filter.AttributeExpression)
	if !ok || comparison.Operator != filter.EQ ||
		!strings.EqualFold(comparison.AttributePath.AttributeName, attribute) {
		return "", false
	}
	value, ok := comparison.CompareValue.(string)
	return value, ok
}

func stringMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case scimlib.ResourceAttributes:
		return map[string]any(typed), true
	default:
		return nil, false
	}
}

func appendComplexValues(current, additions any) []any {
	result := interfaceSlice(current)
	for _, addition := range interfaceSlice(additions) {
		additionMap, ok := stringMap(addition)
		if !ok {
			continue
		}
		value, _ := additionMap["value"].(string)
		if value == "" || complexValuePresent(result, value) {
			continue
		}
		result = append(result, addition)
	}
	return result
}

func removeComplexValue(current any, target string) []any {
	values := interfaceSlice(current)
	result := make([]any, 0, len(values))
	for _, value := range values {
		valueMap, ok := stringMap(value)
		if ok {
			if memberValue, _ := valueMap["value"].(string); memberValue == target {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func complexValuePresent(values []any, target string) bool {
	for _, value := range values {
		valueMap, ok := stringMap(value)
		if !ok {
			continue
		}
		if memberValue, _ := valueMap["value"].(string); memberValue == target {
			return true
		}
	}
	return false
}

func interfaceSlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return append([]any(nil), typed...)
	case nil:
		return []any{}
	default:
		return []any{typed}
	}
}

func (s *Service) wakeWorker() {
	select {
	case s.signal <- struct{}{}:
	default:
	}
}
