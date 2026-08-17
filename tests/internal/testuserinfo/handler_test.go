// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package testuserinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/envoyproxy/ai-gateway/tests/internal/testextauth"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	server := &Server{Users: map[string]testextauth.UserInfo{
		"valid-token": {Subject: "user-123", Tier: "premium"},
	}}

	t.Run("returns UserInfo", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		request.Header.Set("Authorization", "Bearer valid-token")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.JSONEq(t, `{"sub":"user-123","tier":"premium"}`, response.Body.String())
	})

	t.Run("rejects unknown token", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		request.Header.Set("Authorization", "Bearer unknown-token")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)

		require.Equal(t, http.StatusUnauthorized, response.Code)
	})

	t.Run("returns default UserInfo", func(t *testing.T) {
		server.Default = &testextauth.UserInfo{
			Subject:  "local-user",
			Tier:     "basic",
			Projects: []string{"project-123"},
		}
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		request.Header.Set("Authorization", "Bearer another-token")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.JSONEq(t, `{"sub":"local-user","tier":"basic","projects":["project-123"]}`, response.Body.String())
	})
}
