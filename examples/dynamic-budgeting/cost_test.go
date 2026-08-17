// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package main

import (
	"testing"

	"github.com/envoyproxy/ai-gateway/internal/llmcostcel"
	"github.com/stretchr/testify/require"
)

func TestDollarCostCEL(t *testing.T) {
	program, err := llmcostcel.NewProgram("input_tokens * uint(200) + output_tokens * uint(800)")
	require.NoError(t, err)

	cost, err := llmcostcel.EvaluateProgram(program, "dynamic-budgeting-model", "", "", 1, 0, 0, 1, 2, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1_000), cost)
}
