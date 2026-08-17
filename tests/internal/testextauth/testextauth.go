// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package testextauth

const (
	// ExtAuthModeEnvVar selects the authorization implementation. The default mode
	// preserves the deterministic header-driven behavior used by existing tests.
	ExtAuthModeEnvVar = "EXT_AUTH_MODE"
	// ExtAuthJWTUserInfoMode enables local JWT -> UserInfo -> tier lookup authorization.
	ExtAuthJWTUserInfoMode = "jwt-userinfo"

	// ExtAuthAccessControlHeader is the header used to send the access control value to
	// configure the response that will be returned by the ext-authz filter.
	ExtAuthAccessControlHeader = "x-access-control"

	// ExtAuthAllowedValueEnvVar is the name of the environment variable that will configure
	// the allowed value for the access control header. If not set, all requests are allowed.
	ExtAuthAllowedValueEnvVar = "EXT_AUTH_ALLOWED_VALUE"

	// ExtAuthDynamicMetadataHeaderEnvVar names the request header whose value picks which dynamic
	// metadata the server returns on an allowed response. ext_authz exposes that metadata under the
	// envoy.filters.http.ext_authz namespace.
	ExtAuthDynamicMetadataHeaderEnvVar = "EXT_AUTH_DYNAMIC_METADATA_HEADER"

	// ExtAuthDynamicMetadataByHeaderEnvVar is a JSON object mapping a value of that header to the
	// fields to emit. Values are arbitrary JSON, so a field can be the struct Envoy's rate limit
	// override reads:
	//
	//	{"premium": {"millidollar_daily_limit": {"requests_per_unit": 6000, "unit": "DAY"}}}
	//
	// A header value with no entry gets no metadata at all, which is how a test covers the "source
	// said nothing about this request" case. Nothing is emitted unless both env vars are set.
	ExtAuthDynamicMetadataByHeaderEnvVar = "EXT_AUTH_DYNAMIC_METADATA_BY_HEADER"

	// ExtAuthJWTSecretEnvVar configures the local-development HS256 signing key.
	ExtAuthJWTSecretEnvVar = "EXT_AUTH_JWT_SECRET"
	// ExtAuthJWTIssuerEnvVar optionally configures the expected JWT issuer.
	ExtAuthJWTIssuerEnvVar = "EXT_AUTH_JWT_ISSUER"
	// ExtAuthJWTAudienceEnvVar optionally configures the expected JWT audience.
	ExtAuthJWTAudienceEnvVar = "EXT_AUTH_JWT_AUDIENCE"
	// ExtAuthUserInfoURLVar configures the UserInfo endpoint.
	ExtAuthUserInfoURLVar = "EXT_AUTH_USERINFO_URL"
	// ExtAuthTierLimitsEnvVar configures tier limits as a JSON object.
	ExtAuthTierLimitsEnvVar = "EXT_AUTH_TIER_LIMITS"
	// ExtAuthProjectLimitsEnvVar configures shared project allocation limits.
	ExtAuthProjectLimitsEnvVar = "EXT_AUTH_PROJECT_LIMITS"
	// ExtAuthDynamicMetadataKeyEnvVar is the compatibility key for a single
	// daily budget.
	ExtAuthDynamicMetadataKeyEnvVar = "EXT_AUTH_DYNAMIC_METADATA_KEY"
	// ExtAuthDailyMetadataKeyEnvVar configures the daily budget metadata key.
	ExtAuthDailyMetadataKeyEnvVar = "EXT_AUTH_DAILY_METADATA_KEY"
	// ExtAuthMonthlyMetadataKeyEnvVar configures the monthly budget metadata key.
	ExtAuthMonthlyMetadataKeyEnvVar = "EXT_AUTH_MONTHLY_METADATA_KEY"
	// ExtAuthUserDailyMetadataKeyEnvVar configures the regular user daily budget key.
	ExtAuthUserDailyMetadataKeyEnvVar = "EXT_AUTH_USER_DAILY_METADATA_KEY"
	// ExtAuthUserMonthlyMetadataKeyEnvVar configures the regular user monthly budget key.
	ExtAuthUserMonthlyMetadataKeyEnvVar = "EXT_AUTH_USER_MONTHLY_METADATA_KEY"
	// ExtAuthProjectDailyMetadataKeyEnvVar configures the project daily budget key.
	ExtAuthProjectDailyMetadataKeyEnvVar = "EXT_AUTH_PROJECT_DAILY_METADATA_KEY"
	// ExtAuthProjectMonthlyMetadataKeyEnvVar configures the project monthly budget key.
	ExtAuthProjectMonthlyMetadataKeyEnvVar = "EXT_AUTH_PROJECT_MONTHLY_METADATA_KEY"
)
