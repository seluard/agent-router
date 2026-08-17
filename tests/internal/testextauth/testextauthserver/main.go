// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/envoyproxy/ai-gateway/internal/json"
	"github.com/envoyproxy/ai-gateway/tests/internal/testextauth"
)

var logger = log.New(os.Stdout, "[testextauthz] ", 0)

func main() {
	srv := doMain()
	defer srv.Stop()

	// Block until a terminate signal is received (SIGINT or SIGTERM).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigCh
	logger.Printf("received signal %v, shutting down", s)
}

func doMain() *grpc.Server {
	portStr := os.Getenv("LISTENER_PORT")
	if portStr == "" {
		portStr = "1073"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		logger.Fatalf("invalid port: %v", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}

	server := grpc.NewServer()
	authServer := authorizationServer()
	authv3.RegisterAuthorizationServer(server, authServer)

	go func() {
		logger.Printf("starting ext auth server on port: %d", port)
		if err := server.Serve(lis); err != nil {
			logger.Fatalf("failed to serve: %v", err)
		}
	}()

	return server
}

func authorizationServer() authv3.AuthorizationServer {
	if os.Getenv(testextauth.ExtAuthModeEnvVar) != testextauth.ExtAuthJWTUserInfoMode {
		return &ExtAuthServer{
			AllowedHeaderValue: os.Getenv(testextauth.ExtAuthAllowedValueEnvVar),
			MetadataHeader:     os.Getenv(testextauth.ExtAuthDynamicMetadataHeaderEnvVar),
			MetadataByHeader:   parseMetadataByHeader(os.Getenv(testextauth.ExtAuthDynamicMetadataByHeaderEnvVar)),
		}
	}

	secret := os.Getenv(testextauth.ExtAuthJWTSecretEnvVar)
	if secret == "" {
		logger.Fatalf("%s must be set when %s=%s", testextauth.ExtAuthJWTSecretEnvVar, testextauth.ExtAuthModeEnvVar, testextauth.ExtAuthJWTUserInfoMode)
	}
	userInfoURL := os.Getenv(testextauth.ExtAuthUserInfoURLVar)
	if userInfoURL == "" {
		logger.Fatalf("%s must be set when %s=%s", testextauth.ExtAuthUserInfoURLVar, testextauth.ExtAuthModeEnvVar, testextauth.ExtAuthJWTUserInfoMode)
	}

	limitsJSON := os.Getenv(testextauth.ExtAuthTierLimitsEnvVar)
	if limitsJSON == "" {
		logger.Fatalf("%s must be set when %s=%s", testextauth.ExtAuthTierLimitsEnvVar, testextauth.ExtAuthModeEnvVar, testextauth.ExtAuthJWTUserInfoMode)
	}
	var limits map[string]testextauth.TierLimits
	if err := json.Unmarshal([]byte(limitsJSON), &limits); err != nil {
		logger.Fatalf("invalid %s: %v", testextauth.ExtAuthTierLimitsEnvVar, err)
	}
	var projectLimits map[string]testextauth.TierLimits
	if value := os.Getenv(testextauth.ExtAuthProjectLimitsEnvVar); value != "" {
		if err := json.Unmarshal([]byte(value), &projectLimits); err != nil {
			logger.Fatalf("invalid %s: %v", testextauth.ExtAuthProjectLimitsEnvVar, err)
		}
	}

	logger.Printf("using JWT UserInfo authorization mode")
	return &testextauth.JWTUserInfoServer{
		Verifier: testextauth.HMACTokenVerifier{
			Key:      []byte(secret),
			Issuer:   os.Getenv(testextauth.ExtAuthJWTIssuerEnvVar),
			Audience: os.Getenv(testextauth.ExtAuthJWTAudienceEnvVar),
		},
		UserInfo: &testextauth.HTTPUserInfoClient{URL: userInfoURL},
		Tiers:    testextauth.MemoryTierStore(limits),
		Projects: testextauth.MemoryProjectStore(projectLimits),
		MetadataKeys: testextauth.MetadataKeys{
			Daily:          firstNonEmpty(os.Getenv(testextauth.ExtAuthDailyMetadataKeyEnvVar), os.Getenv(testextauth.ExtAuthDynamicMetadataKeyEnvVar)),
			Monthly:        os.Getenv(testextauth.ExtAuthMonthlyMetadataKeyEnvVar),
			UserDaily:      os.Getenv(testextauth.ExtAuthUserDailyMetadataKeyEnvVar),
			UserMonthly:    os.Getenv(testextauth.ExtAuthUserMonthlyMetadataKeyEnvVar),
			ProjectDaily:   os.Getenv(testextauth.ExtAuthProjectDailyMetadataKeyEnvVar),
			ProjectMonthly: os.Getenv(testextauth.ExtAuthProjectMonthlyMetadataKeyEnvVar),
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// parseMetadataByHeader parses a JSON object mapping a header value to the metadata fields to emit.
// Malformed JSON is fatal rather than ignored, because a test that silently got no metadata would
// look like a product failure.
func parseMetadataByHeader(s string) map[string]map[string]any {
	if s == "" {
		return nil
	}
	var out map[string]map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		logger.Fatalf("invalid %s: %v", testextauth.ExtAuthDynamicMetadataByHeaderEnvVar, err)
	}
	return out
}

type ExtAuthServer struct {
	AllowedHeaderValue string
	// MetadataHeader is the request header whose value picks the entry in MetadataByHeader.
	MetadataHeader string
	// MetadataByHeader maps a value of MetadataHeader to the fields emitted in
	// CheckResponse.dynamic_metadata on an allowed response. ext_authz exposes them under the
	// envoy.filters.http.ext_authz namespace. A header value that isn't in the map gets no metadata
	// at all, which is how a test covers "the source said nothing about this request".
	MetadataByHeader map[string]map[string]any
}

// metadataFor returns the dynamic metadata to emit for this request, or nil to emit none.
func (e *ExtAuthServer) metadataFor(headers map[string]string) *structpb.Struct {
	if e.MetadataHeader == "" || len(e.MetadataByHeader) == 0 {
		return nil
	}
	fields, ok := e.MetadataByHeader[headers[e.MetadataHeader]]
	if !ok {
		return nil
	}
	md, err := structpb.NewStruct(fields)
	if err != nil {
		logger.Fatalf("cannot convert metadata for %q to a struct: %v", headers[e.MetadataHeader], err)
	}
	return md
}

func (e *ExtAuthServer) Check(_ context.Context, req *authv3.CheckRequest) (response *authv3.CheckResponse, err error) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	logger.Printf("checking request with headers: %v", headers)

	allowed := e.AllowedHeaderValue == "" ||
		(headers != nil && headers[testextauth.ExtAuthAccessControlHeader] == e.AllowedHeaderValue)
	if !allowed {
		logger.Printf("access control does not match %q. denied.", e.AllowedHeaderValue)
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.PermissionDenied), Message: "access denied"}}, nil
	}

	logger.Println("request allowed")
	resp := &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.OK)}}
	if md := e.metadataFor(headers); md != nil {
		logger.Printf("emitting dynamic metadata %v", md.AsMap())
		resp.DynamicMetadata = md
	} else {
		logger.Println("no dynamic metadata for this request")
	}
	return resp, nil
}
