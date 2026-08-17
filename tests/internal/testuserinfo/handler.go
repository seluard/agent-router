// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package testuserinfo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/envoyproxy/ai-gateway/tests/internal/testextauth"
)

// Server is a deterministic UserInfo endpoint for local development and tests.
// Users is keyed by the bearer token presented to /userinfo.
type Server struct {
	Users   map[string]testextauth.UserInfo
	Default *testextauth.UserInfo
}

// ServeHTTP implements the UserInfo HTTP endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/userinfo" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	userInfo, ok := s.Users[token]
	if !ok {
		if s.Default == nil {
			http.Error(w, "unknown bearer token", http.StatusUnauthorized)
			return
		}
		userInfo = *s.Default
	}
	if userInfo.Subject == "" || userInfo.Tier == "" {
		http.Error(w, "invalid UserInfo fixture", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		http.Error(w, fmt.Sprintf("encode UserInfo response: %v", err), http.StatusInternalServerError)
	}
}

func bearerToken(value string) (string, bool) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
