// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package testextauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestJWTUserInfoServerCheck(t *testing.T) {
	const secret = "local-development-secret"
	token := signedToken(t, secret, "user-123")
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"sub":"user-123","tier":"premium"}`))
		require.NoError(t, err)
	}))
	defer userInfoServer.Close()

	server := &JWTUserInfoServer{
		Verifier: HMACTokenVerifier{Key: []byte(secret)},
		UserInfo: &HTTPUserInfoClient{URL: userInfoServer.URL},
		Tiers: MemoryTierStore{
			"premium": {
				Daily:   TierLimit{RequestsPerUnit: 100, Unit: "DAY"},
				Monthly: TierLimit{RequestsPerUnit: 1000, Unit: "MONTH"},
			},
		},
	}

	response, err := server.Check(t.Context(), checkRequest(token))
	require.NoError(t, err)
	require.Equal(t, int32(codes.OK), response.GetStatus().GetCode())
	require.Equal(t, map[string]string{
		"x-user-id":                 "user-123",
		"x-user-tier":               "premium",
		"x-quota-scope-type":        "user",
		"x-quota-scope-id":          "user-123",
		"x-user-daily-limit":        "100",
		"x-user-daily-limit-unit":   "DAY",
		"x-user-monthly-limit":      "1000",
		"x-user-monthly-limit-unit": "MONTH",
	}, responseHeaders(response))
	require.Nil(t, response.GetDynamicMetadata())

	t.Run("emits optional limit metadata", func(t *testing.T) {
		server.MetadataKeys = MetadataKeys{
			Daily: "millidollar_daily_limit", Monthly: "millidollar_monthly_limit",
		}
		response, err := server.Check(t.Context(), checkRequest(token))
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"millidollar_daily_limit": map[string]any{
				"requests_per_unit": float64(100),
				"unit":              "DAY",
			},
			"millidollar_monthly_limit": map[string]any{
				"requests_per_unit": float64(1000),
				"unit":              "MONTH",
			},
		}, response.GetDynamicMetadata().AsMap())
		require.Equal(t, "premium", responseHeaders(response)["x-user-tier"])
	})
}

func TestJWTUserInfoServerProjectAllocation(t *testing.T) {
	const secret = "project-secret"
	token := signedToken(t, secret, "user-123")
	server := &JWTUserInfoServer{
		Verifier: HMACTokenVerifier{Key: []byte(secret)},
		UserInfo: &staticUserInfoClient{info: UserInfo{
			Subject:  "user-123",
			Tier:     "basic",
			Projects: []string{"project-123"},
		}},
		Tiers: MemoryTierStore{"basic": {
			Daily:   TierLimit{RequestsPerUnit: 2000, Unit: "DAY"},
			Monthly: TierLimit{RequestsPerUnit: 20000, Unit: "MONTH"},
		}},
		Projects: MemoryProjectStore{"project-123": {
			Daily:   TierLimit{RequestsPerUnit: 6000, Unit: "DAY"},
			Monthly: TierLimit{RequestsPerUnit: 60000, Unit: "MONTH"},
		}},
		MetadataKeys: MetadataKeys{
			UserDaily: "user_millidollar_daily_limit", UserMonthly: "user_millidollar_monthly_limit",
			ProjectDaily: "project_millidollar_daily_limit", ProjectMonthly: "project_millidollar_monthly_limit",
		},
	}

	response, err := server.Check(t.Context(), checkRequestWithProject(token, "project-123"))
	require.NoError(t, err)
	require.Equal(t, int32(codes.OK), response.GetStatus().GetCode())
	require.Equal(t, "project", responseHeaders(response)["x-quota-scope-type"])
	require.Equal(t, "project-123", responseHeaders(response)["x-quota-scope-id"])
	require.Equal(t, map[string]any{
		"project_millidollar_daily_limit": map[string]any{
			"requests_per_unit": float64(6000), "unit": "DAY",
		},
		"project_millidollar_monthly_limit": map[string]any{
			"requests_per_unit": float64(60000), "unit": "MONTH",
		},
	}, response.GetDynamicMetadata().AsMap())

	response, err = server.Check(t.Context(), checkRequest(token))
	require.NoError(t, err)
	require.Equal(t, "user", responseHeaders(response)["x-quota-scope-type"])
	require.Equal(t, "user-123", responseHeaders(response)["x-quota-scope-id"])
	require.Equal(t, map[string]any{
		"user_millidollar_daily_limit": map[string]any{
			"requests_per_unit": float64(2000), "unit": "DAY",
		},
		"user_millidollar_monthly_limit": map[string]any{
			"requests_per_unit": float64(20000), "unit": "MONTH",
		},
	}, response.GetDynamicMetadata().AsMap())

	response, err = server.Check(t.Context(), checkRequestWithProject(token, "project-unauthorized"))
	require.NoError(t, err)
	require.Equal(t, int32(codes.PermissionDenied), response.GetStatus().GetCode())
}

func TestJWTUserInfoServerCheckErrors(t *testing.T) {
	server := &JWTUserInfoServer{
		Verifier: HMACTokenVerifier{Key: []byte("secret")},
		UserInfo: &staticUserInfoClient{info: UserInfo{Subject: "different", Tier: "basic"}},
		Tiers: MemoryTierStore{"basic": {
			Daily:   TierLimit{RequestsPerUnit: 1, Unit: "DAY"},
			Monthly: TierLimit{RequestsPerUnit: 1, Unit: "MONTH"},
		}},
	}

	tests := []struct {
		name  string
		token string
		code  codes.Code
	}{
		{name: "missing bearer token", code: codes.Unauthenticated},
		{name: "invalid token", token: "not-a-jwt", code: codes.Unauthenticated},
		{name: "expired token", token: expiredToken(t, "secret", "user-123"), code: codes.Unauthenticated},
		{name: "userinfo subject mismatch", token: signedToken(t, "secret", "user-123"), code: codes.PermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := server.Check(t.Context(), checkRequest(test.token))
			require.NoError(t, err)
			require.Equal(t, int32(test.code), response.GetStatus().GetCode())
		})
	}
}

func TestJWTUserInfoServerCheckDependencyFailures(t *testing.T) {
	token := signedToken(t, "secret", "user-123")
	t.Run("userinfo unavailable", func(t *testing.T) {
		server := &JWTUserInfoServer{
			Verifier: HMACTokenVerifier{Key: []byte("secret")},
			UserInfo: &staticUserInfoClient{err: errors.New("userinfo unavailable")},
			Tiers: MemoryTierStore{"premium": {
				Daily:   TierLimit{RequestsPerUnit: 1, Unit: "DAY"},
				Monthly: TierLimit{RequestsPerUnit: 1, Unit: "MONTH"},
			}},
		}
		response, err := server.Check(t.Context(), checkRequest(token))
		require.NoError(t, err)
		require.Equal(t, int32(codes.Unavailable), response.GetStatus().GetCode())
	})

	t.Run("unknown tier", func(t *testing.T) {
		server := &JWTUserInfoServer{
			Verifier: HMACTokenVerifier{Key: []byte("secret")},
			UserInfo: &staticUserInfoClient{info: UserInfo{Subject: "user-123", Tier: "unknown"}},
			Tiers: MemoryTierStore{"premium": {
				Daily:   TierLimit{RequestsPerUnit: 1, Unit: "DAY"},
				Monthly: TierLimit{RequestsPerUnit: 1, Unit: "MONTH"},
			}},
		}
		response, err := server.Check(t.Context(), checkRequest(token))
		require.NoError(t, err)
		require.Equal(t, int32(codes.PermissionDenied), response.GetStatus().GetCode())
	})
}

func TestHTTPUserInfoClient(t *testing.T) {
	t.Run("dependency failure", func(t *testing.T) {
		client := &HTTPUserInfoClient{
			URL: "http://127.0.0.1:1",
			Client: &http.Client{
				Timeout: 100 * time.Millisecond,
			},
		}
		_, err := client.Fetch(context.Background(), "token")
		require.Error(t, err)
	})
}

func signedToken(t *testing.T, secret, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})
	signed, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func expiredToken(t *testing.T, secret, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	})
	signed, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func checkRequest(token string) *authv3.CheckRequest {
	return checkRequestWithProject(token, "")
}

func checkRequestWithProject(token, projectID string) *authv3.CheckRequest {
	headers := map[string]string{"authorization": "Bearer " + token}
	if projectID != "" {
		headers["x-project-id"] = projectID
	}
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: headers,
				},
			},
		},
	}
}

func responseHeaders(response *authv3.CheckResponse) map[string]string {
	result := make(map[string]string)
	for _, option := range response.GetOkResponse().GetHeaders() {
		result[option.GetHeader().GetKey()] = option.GetHeader().GetValue()
	}
	return result
}

type staticUserInfoClient struct {
	info UserInfo
	err  error
}

func (c *staticUserInfoClient) Fetch(context.Context, string) (UserInfo, error) {
	return c.info, c.err
}
