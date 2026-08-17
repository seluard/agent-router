// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package testextauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

// UserInfo is the subset of an OpenID Connect UserInfo response required by the
// local authorization flow.
type UserInfo struct {
	Subject  string   `json:"sub"`
	Tier     string   `json:"tier"`
	Projects []string `json:"projects,omitempty"`
}

// TierLimit is one time-window budget associated with a tier.
type TierLimit struct {
	RequestsPerUnit int64  `json:"requests_per_unit"`
	Unit            string `json:"unit"`
}

// TierLimits contains the independent daily and monthly budgets for a tier.
type TierLimits struct {
	Daily   TierLimit `json:"daily"`
	Monthly TierLimit `json:"monthly"`
}

// UserInfoClient resolves a bearer token through an identity provider's
// UserInfo endpoint.
type UserInfoClient interface {
	Fetch(ctx context.Context, accessToken string) (UserInfo, error)
}

// TierStore resolves a tier to its configured limit.
type TierStore interface {
	Lookup(ctx context.Context, tier string) (TierLimits, error)
}

// ProjectStore resolves a shared project allocation to its budgets.
type ProjectStore interface {
	Lookup(ctx context.Context, projectID string) (TierLimits, error)
}

// HMACTokenVerifier validates local-development HS256 tokens. Production
// deployments should use an issuer's JWKS-backed verifier instead.
type HMACTokenVerifier struct {
	Key      []byte
	Issuer   string
	Audience string
}

// Verify validates a bearer token and returns its subject.
func (v HMACTokenVerifier) Verify(_ context.Context, rawToken string) (string, error) {
	if len(v.Key) == 0 {
		return "", fmt.Errorf("JWT signing key is not configured")
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})).ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method == nil {
				return nil, fmt.Errorf("JWT signing method is missing")
			}
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected JWT signing method %q", token.Method.Alg())
			}
			return v.Key, nil
		},
	)
	if err != nil {
		return "", fmt.Errorf("invalid JWT: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid JWT")
	}
	if v.Issuer != "" && claims.Issuer != v.Issuer {
		return "", fmt.Errorf("JWT issuer %q does not match configured issuer", claims.Issuer)
	}
	if v.Audience != "" {
		audienceMatches := false
		for _, audience := range claims.Audience {
			if audience == v.Audience {
				audienceMatches = true
				break
			}
		}
		if !audienceMatches {
			return "", fmt.Errorf("JWT audience does not include configured audience")
		}
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("JWT subject is missing")
	}
	return claims.Subject, nil
}

// HTTPUserInfoClient calls a UserInfo endpoint with the original bearer token.
type HTTPUserInfoClient struct {
	URL    string
	Client *http.Client
}

// Fetch implements UserInfoClient.
func (c *HTTPUserInfoClient) Fetch(ctx context.Context, accessToken string) (UserInfo, error) {
	if c == nil || c.URL == "" {
		return UserInfo{}, fmt.Errorf("UserInfo URL is not configured")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return UserInfo{}, fmt.Errorf("create UserInfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("call UserInfo endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return UserInfo{}, fmt.Errorf("UserInfo endpoint returned HTTP %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, fmt.Errorf("decode UserInfo response: %w", err)
	}
	if userInfo.Subject == "" {
		return UserInfo{}, fmt.Errorf("UserInfo response subject is missing")
	}
	if userInfo.Tier == "" {
		return UserInfo{}, fmt.Errorf("UserInfo response tier is missing")
	}
	return userInfo, nil
}

// MemoryTierStore is a deterministic local tier store.
type MemoryTierStore map[string]TierLimits

// Lookup implements TierStore.
func (s MemoryTierStore) Lookup(_ context.Context, tier string) (TierLimits, error) {
	limit, ok := s[tier]
	if !ok {
		return TierLimits{}, fmt.Errorf("tier %q is not configured", tier)
	}
	if err := validateTierLimits(limit, fmt.Sprintf("tier %q", tier)); err != nil {
		return TierLimits{}, err
	}
	return limit, nil
}

// MemoryProjectStore is a deterministic local project allocation store.
type MemoryProjectStore map[string]TierLimits

// Lookup implements ProjectStore.
func (s MemoryProjectStore) Lookup(_ context.Context, projectID string) (TierLimits, error) {
	limits, ok := s[projectID]
	if !ok {
		return TierLimits{}, fmt.Errorf("project %q is not configured", projectID)
	}
	if err := validateTierLimits(limits, fmt.Sprintf("project %q", projectID)); err != nil {
		return TierLimits{}, err
	}
	return limits, nil
}

func validateTierLimits(limits TierLimits, name string) error {
	for window, budget := range map[string]TierLimit{"daily": limits.Daily, "monthly": limits.Monthly} {
		if budget.RequestsPerUnit < 0 || budget.Unit == "" {
			return fmt.Errorf("%s has an invalid %s limit", name, window)
		}
	}
	return nil
}

// JWTUserInfoServer is the local JWT -> UserInfo -> budget authorization
// service used by the dynamic-budgeting example.
type JWTUserInfoServer struct {
	Verifier     HMACTokenVerifier
	UserInfo     UserInfoClient
	Tiers        TierStore
	Projects     ProjectStore
	HeaderIDs    HeaderNames
	MetadataKeys MetadataKeys
	// MetadataKey is retained for compatibility with the original single-window
	// prototype and maps to the daily budget when MetadataKeys.Daily is empty.
	MetadataKey string
}

// MetadataKeys controls the dynamic metadata keys emitted for each budget.
type MetadataKeys struct {
	Daily          string
	Monthly        string
	UserDaily      string
	UserMonthly    string
	ProjectDaily   string
	ProjectMonthly string
}

// HeaderNames controls the request headers added by an allowed authorization
// response.
type HeaderNames struct {
	Subject      string
	Tier         string
	ScopeType    string
	ScopeID      string
	DailyLimit   string
	DailyUnit    string
	MonthlyLimit string
	MonthlyUnit  string
}

func (h HeaderNames) withDefaults() HeaderNames {
	if h.Subject == "" {
		h.Subject = "x-user-id"
	}
	if h.Tier == "" {
		h.Tier = "x-user-tier"
	}
	if h.ScopeType == "" {
		h.ScopeType = "x-quota-scope-type"
	}
	if h.ScopeID == "" {
		h.ScopeID = "x-quota-scope-id"
	}
	if h.DailyLimit == "" {
		h.DailyLimit = "x-user-daily-limit"
	}
	if h.DailyUnit == "" {
		h.DailyUnit = "x-user-daily-limit-unit"
	}
	if h.MonthlyLimit == "" {
		h.MonthlyLimit = "x-user-monthly-limit"
	}
	if h.MonthlyUnit == "" {
		h.MonthlyUnit = "x-user-monthly-limit-unit"
	}
	return h
}

// Check implements Envoy's gRPC Authorization service.
func (s *JWTUserInfoServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	accessToken, err := bearerToken(headers["authorization"])
	if err != nil {
		return denied(codes.Unauthenticated, err), nil
	}

	subject, err := s.Verifier.Verify(ctx, accessToken)
	if err != nil {
		return denied(codes.Unauthenticated, err), nil
	}
	if s.UserInfo == nil {
		return denied(codes.FailedPrecondition, fmt.Errorf("UserInfo client is not configured")), nil
	}
	userInfo, err := s.UserInfo.Fetch(ctx, accessToken)
	if err != nil {
		return denied(codes.Unavailable, err), nil
	}
	if userInfo.Subject != subject {
		return denied(codes.PermissionDenied, fmt.Errorf("UserInfo subject does not match JWT subject")), nil
	}

	projectID := strings.TrimSpace(headers["x-project-id"])
	scopeType := "user"
	scopeID := subject
	var limits TierLimits
	metadataKeys := s.MetadataKeys
	if metadataKeys.UserDaily == "" {
		metadataKeys.UserDaily = metadataKeys.Daily
	}
	if metadataKeys.UserMonthly == "" {
		metadataKeys.UserMonthly = metadataKeys.Monthly
	}
	if metadataKeys.ProjectDaily == "" {
		metadataKeys.ProjectDaily = metadataKeys.UserDaily
	}
	if metadataKeys.ProjectMonthly == "" {
		metadataKeys.ProjectMonthly = metadataKeys.UserMonthly
	}
	if metadataKeys.UserDaily == "" && s.MetadataKey != "" {
		metadataKeys.UserDaily = s.MetadataKey
	}
	if projectID != "" {
		if !contains(userInfo.Projects, projectID) {
			return denied(codes.PermissionDenied, fmt.Errorf("user %q is not a member of project %q", subject, projectID)), nil
		}
		if s.Projects == nil {
			return denied(codes.FailedPrecondition, fmt.Errorf("project store is not configured")), nil
		}
		limits, err = s.Projects.Lookup(ctx, projectID)
		scopeType = "project"
		scopeID = projectID
		metadataKeys.Daily = metadataKeys.ProjectDaily
		metadataKeys.Monthly = metadataKeys.ProjectMonthly
	} else {
		if s.Tiers == nil {
			return denied(codes.FailedPrecondition, fmt.Errorf("tier store is not configured")), nil
		}
		limits, err = s.Tiers.Lookup(ctx, userInfo.Tier)
		metadataKeys.Daily = metadataKeys.UserDaily
		metadataKeys.Monthly = metadataKeys.UserMonthly
	}
	if err != nil {
		return denied(codes.PermissionDenied, err), nil
	}

	h := s.HeaderIDs.withDefaults()
	responseHeaders := []*corev3.HeaderValueOption{
		header(h.Subject, subject),
		header(h.Tier, userInfo.Tier),
		header(h.ScopeType, scopeType),
		header(h.ScopeID, scopeID),
		header(h.DailyLimit, fmt.Sprintf("%d", limits.Daily.RequestsPerUnit)),
		header(h.DailyUnit, limits.Daily.Unit),
		header(h.MonthlyLimit, fmt.Sprintf("%d", limits.Monthly.RequestsPerUnit)),
		header(h.MonthlyUnit, limits.Monthly.Unit),
	}
	metadata, err := metadataFor(metadataKeys, limits)
	if err != nil {
		return denied(codes.Internal, err), nil
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{Headers: responseHeaders},
		},
		DynamicMetadata: metadata,
	}, nil
}

func metadataFor(keys MetadataKeys, limits TierLimits) (*structpb.Struct, error) {
	if keys.Daily == "" && keys.Monthly == "" {
		return nil, nil
	}
	fields := make(map[string]any, 2)
	if keys.Daily != "" {
		fields[keys.Daily] = metadataLimit(limits.Daily)
	}
	if keys.Monthly != "" {
		fields[keys.Monthly] = metadataLimit(limits.Monthly)
	}
	metadata, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("build dynamic metadata: %w", err)
	}
	return metadata, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func metadataLimit(limit TierLimit) map[string]any {
	return map[string]any{
		"requests_per_unit": float64(limit.RequestsPerUnit),
		"unit":              limit.Unit,
	}
}

func bearerToken(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", fmt.Errorf("Authorization header must contain a bearer token")
	}
	return parts[1], nil
}

func header(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   name,
			Value: value,
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func denied(code codes.Code, err error) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(code), Message: err.Error()},
	}
}

var _ authv3.AuthorizationServer = (*JWTUserInfoServer)(nil)
var _ TierStore = MemoryTierStore(nil)
var _ UserInfoClient = (*HTTPUserInfoClient)(nil)
