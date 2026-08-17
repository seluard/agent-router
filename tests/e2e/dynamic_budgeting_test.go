// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/tests/internal/e2elib"
	"github.com/envoyproxy/ai-gateway/tests/internal/testextauth"
	"github.com/envoyproxy/ai-gateway/tests/internal/testupstreamlib"
)

func Test_Examples_DynamicBudgeting(t *testing.T) {
	if !e2elib.EnvoyGatewaySupportsLimitFromMetadata() {
		t.Skipf("needs Envoy Gateway %s, have %s", e2elib.EnvoyGatewayLatestVersion, e2elib.EnvoyGatewayVersion())
	}

	require.NoError(t, e2elib.KubectlApplyManifest(t.Context(), "../../examples/token_ratelimit/redis.yaml"))
	t.Cleanup(func() {
		_ = e2elib.KubectlDeleteManifest(context.Background(), "../../examples/token_ratelimit/redis.yaml")
	})

	projectID := fmt.Sprintf("dynamic-budget-project-%d", time.Now().UnixNano())
	userID := fmt.Sprintf("dynamic-budget-user-%d", time.Now().UnixNano())
	manifestBytes, err := os.ReadFile("../../examples/dynamic-budgeting/dynamic-budgeting.yaml")
	require.NoError(t, err)
	manifest := strings.ReplaceAll(string(manifestBytes), "project-123", projectID)
	manifest = strings.ReplaceAll(manifest, "local-user", userID)
	require.NoError(t, e2elib.KubectlApplyManifestStdin(t.Context(), manifest))
	t.Cleanup(func() {
		_ = e2elib.KubectlDeleteManifestStdin(context.Background(), manifest)
	})

	const userInfoDeployment = "envoy-ai-gateway-dynamic-budgeting-userinfo"
	e2elib.RequireWaitForGatewayPodReady(t, "gateway.envoyproxy.io/owning-gateway-name=envoy-ai-gateway-dynamic-budgeting")
	e2elib.RequireWaitForPodReady(t, "default", "app=envoy-ai-gateway-dynamic-budgeting-extauth")
	e2elib.RequireWaitForPodReady(t, "default", "app=envoy-ai-gateway-dynamic-budgeting-userinfo")
	e2elib.RequireWaitForPodReady(t, "default", "app=envoy-ai-gateway-dynamic-budgeting-testupstream")
	e2elib.RequireWaitForPodReady(t, "redis-system", "app=redis")
	require.NoError(t, e2elib.KubectlRestartDeployment(t.Context(), e2elib.EnvoyGatewayNamespace, "envoy-ratelimit"))
	e2elib.RequireWaitForPodReady(t, e2elib.EnvoyGatewayNamespace, "app.kubernetes.io/component=ratelimit")

	firstToken := dynamicBudgetingToken(t, userID)
	secondUserID := userID + "-second"
	secondToken := dynamicBudgetingToken(t, secondUserID)
	users, err := json.Marshal(map[string]testextauth.UserInfo{
		secondToken: {
			Subject:  secondUserID,
			Tier:     "basic",
			Projects: []string{projectID},
		},
	})
	require.NoError(t, err)
	setEnv := e2elib.Kubectl(t.Context(), "set", "env", "deployment/"+userInfoDeployment,
		"-n", "default", "USERINFO_USERS="+string(users))
	require.NoError(t, setEnv.Run())
	rollout := e2elib.Kubectl(t.Context(), "rollout", "status", "deployment/"+userInfoDeployment,
		"-n", "default", "--timeout=2m")
	require.NoError(t, rollout.Run())

	fwd := e2elib.RequireNewHTTPPortForwarder(t,
		e2elib.EnvoyGatewayNamespace,
		"gateway.envoyproxy.io/owning-gateway-name=envoy-ai-gateway-dynamic-budgeting",
		e2elib.EnvoyGatewayDefaultServicePort,
	)
	defer fwd.Kill()

	request := func(token, requestedProject string) int {
		t.Helper()
		responseBody := `{"choices":[{"message":{"content":"ok","role":"assistant"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			fwd.Address()+"/v1/chat/completions",
			strings.NewReader(`{"model":"dynamic-budgeting-model","messages":[{"role":"user","content":"hello"}]}`))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Host", "openai.com")
		req.Header.Set("x-ai-eg-model", "dynamic-budgeting-model")
		req.Header.Set(testupstreamlib.ExpectedPathHeaderKey, base64.StdEncoding.EncodeToString([]byte("/v1/chat/completions")))
		req.Header.Set(testupstreamlib.ResponseBodyHeaderKey, base64.StdEncoding.EncodeToString([]byte(responseBody)))
		if requestedProject != "" {
			req.Header.Set("x-project-id", requestedProject)
		}
		response, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		if response.StatusCode != http.StatusOK {
			t.Logf("request status=%d body=%s", response.StatusCode, body)
		}
		return response.StatusCode
	}

	require.Eventually(t, func() bool {
		return request(firstToken, "") == http.StatusOK
	}, 3*time.Minute, 3*time.Second, "dynamic budgeting Gateway did not become ready")

	t.Run("regular user budget is isolated from project budget", func(t *testing.T) {
		for range 6 {
			require.Equal(t, http.StatusOK, request(firstToken, ""))
		}
		require.Equal(t, http.StatusTooManyRequests, request(firstToken, ""))
		require.Equal(t, http.StatusOK, request(firstToken, projectID))
	})

	t.Run("project budget is shared across members", func(t *testing.T) {
		for range 5 {
			require.Equal(t, http.StatusOK, request(firstToken, projectID))
		}
		for range 5 {
			require.Equal(t, http.StatusOK, request(secondToken, projectID))
		}
		require.Equal(t, http.StatusTooManyRequests, request(secondToken, projectID))
	})

	t.Run("unauthorized project is rejected", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, request(firstToken, "not-a-member"))
	})
}

func dynamicBudgetingToken(t *testing.T, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, err := token.SignedString([]byte("local-development-secret"))
	require.NoError(t, err)
	return signed
}
