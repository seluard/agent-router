// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Command token creates a local-only HS256 token for the dynamic-budgeting example.
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	secret := flag.String("secret", "local-development-secret", "HS256 signing secret")
	subject := flag.String("subject", "local-user", "JWT subject")
	tier := flag.String("tier", "", "optional informational tier claim")
	ttl := flag.Duration("ttl", time.Hour, "token lifetime")
	flag.Parse()

	claims := jwt.MapClaims{
		"sub": *subject,
		"exp": time.Now().Add(*ttl).Unix(),
	}
	if *tier != "" {
		claims["tier"] = *tier
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(*secret))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
}
