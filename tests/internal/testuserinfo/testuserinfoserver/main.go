// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
	"github.com/envoyproxy/ai-gateway/tests/internal/testextauth"
	"github.com/envoyproxy/ai-gateway/tests/internal/testuserinfo"
)

var logger = log.New(os.Stdout, "[testuserinfo] ", 0)

func main() {
	port := 1080
	if value := os.Getenv("LISTENER_PORT"); value != "" {
		var err error
		port, err = strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			logger.Fatalf("invalid LISTENER_PORT %q", value)
		}
	}

	usersJSON := os.Getenv("USERINFO_USERS")
	var users map[string]testextauth.UserInfo
	if usersJSON != "" {
		if err := json.Unmarshal([]byte(usersJSON), &users); err != nil {
			logger.Fatalf("invalid USERINFO_USERS: %v", err)
		}
	}

	var defaultUserInfo *testextauth.UserInfo
	if value := os.Getenv("USERINFO_DEFAULT"); value != "" {
		defaultUserInfo = &testextauth.UserInfo{}
		if err := json.Unmarshal([]byte(value), defaultUserInfo); err != nil {
			logger.Fatalf("invalid USERINFO_DEFAULT: %v", err)
		}
	}
	if len(users) == 0 && defaultUserInfo == nil {
		logger.Fatalf("set USERINFO_USERS or USERINFO_DEFAULT")
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           &testuserinfo.Server{Users: users, Default: defaultUserInfo},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Printf("starting UserInfo server on port: %d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("failed to serve: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Println("shutting down")
	if err := server.Shutdown(context.Background()); err != nil {
		logger.Fatalf("failed to shut down: %v", err)
	}
}
