# METADATA
# description: Helper library for JWT verification and decoding in Rego
# entrypoint: true
# authors:
# - The OPA Community
# related_resources:
#   - description: JSON Web Token (JWT) specification
#     ref: https://www.rfc-editor.org/rfc/rfc7519
#   - description: JSON Web Signature (JWS) specification
#     ref: https://www.rfc-editor.org/rfc/rfc7515
#   - description: JSON Web Token Best Current Practices
#     ref: https://www.rfc-editor.org/rfc/rfc8725
#   - description: OpenID Connect Discovery 1.0
#     ref: https://openid.net/specs/openid-connect-discovery-1_0.html
#   - description: OAuth 2.0 Authorization Server Metadata
#     ref: https://datatracker.ietf.org/doc/html/rfc8414
package lib.jwt

import rego.v1

# METADATA
# description: |
#   All algorithms supported by OPA, in uppercase. Note that the symmetric
#   algorithms (HS256, HS384, HS512) are not supported by this library, as using them
#   for anything but development/testing is almost always a bad idea.
supported_algorithms := {
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
}

# METADATA
# description: |
#   - `allowed_issuers` — **must** contain at least one allowed issuer
#   - `time` — time to compare against `exp` if not current time should be used
decode_verify(jwt, config) := result if {
	# regal ignore:with-outside-test-context
	result := _result with _config as object.union(config, {"jwt": jwt})
}

_input_path_jwt := _clean_path(arr) if {
	is_string(data.lib.config.jwt.input_path_jwt)

	path := trim_space(trim_prefix(trim_prefix(data.lib.config.jwt.input_path_jwt, "Bearer"), "bearer"))
	arr := split(path, ".")
}

_input_path_jwt := _clean_path(data.lib.config.jwt.input_path_jwt) if is_array(data.lib.config.jwt.input_path_jwt)

_clean_path(arr) := arr if not arr[0] == "input"

_clean_path(arr) := array.slice(arr, 1, count(arr)) if arr[0] == "input"

# METADATA
# description: the claims of the verified JWT
claims := _verified.claims if {
	count(_verified.claims) > 0
} else := _result.claims if {
	count(_result.claims) > 0
}

# METADATA
# description: the header of the verified JWT
header := _verified.header if {
	count(_verified.header) > 0
} else := _result.header

# METADATA
# description: errors encountered while processing the JWT
errors := _verified.errors if {
	count(_verified.errors) > 0
} else := _result.errors

_config := {}

_decoded := io.jwt.decode(_config.jwt)

_headers := _decoded[0]

_claims := _decoded[1]

_result["errors"] := _errors if count(_errors) > 0

_result["headers"] := _decoded[0] if count(_errors) == 0

_result["claims"] := _decoded[1] if count(_errors) == 0

_keys_provided if count(_config.jwks) > 0

_keys_provided if _config.endpoints.use_oidc_metadata

_keys_provided if _config.endpoints.use_oauth2_metadata

_keys_provided if _config.endpoints.jwks_uri

_verified := decode_verify(input_from_config, data.lib.config.jwt) if {
	input_from_config := object.get(input, _input_path_jwt, null)
	input_from_config != null
}

_jwks := _config.jwks

_errors contains "no signature verification keys provided" if {
	not _keys_provided
}

_errors contains "signature verification failed" if {
	not verify_signature(_config.jwt, _jwks)
}

_errors contains "invalid token: header missing 'alg' value" if {
	not _headers.alg
}

_errors contains sprintf("expected %s algorithm, got %s", [_config.alg, _headers.alg]) if {
	_config.alg != _headers.alg
}

_errors contains sprintf("%s algorithm not supported", [_headers.alg]) if {
	not _headers.alg in supported_algorithms
}

_errors contains "required 'allowed_issuers' missing from configuration" if {
	not _config.allowed_issuers
}

_errors contains "'allowed_issuers' must contain at least one issuer" if {
	count(_config.allowed_issuers) == 0
}

_errors contains sprintf("issuer %s not in list of allowed issuers", [_claims.iss]) if {
	not _claims.iss in _config.allowed_issuers
}

_errors contains "required 'exp' claim not in token" if {
	not _claims.exp
}

_errors contains "token expired" if {
	_time_now > _claims.exp + _leeway
}

_errors contains "current time before 'nbf' (not before) value" if {
	_time_now < _claims.nbf - _leeway
}

_errors contains "configuration requires audience, but no 'aud' claim in token" if {
	object.get(_config, "allowed_audiences", []) != []
	not _token_aud
}

_errors contains "unknown audience (aud) or not allowed" if {
	object.get(_config, "allowed_audiences", []) != []
	not _token_aud_match
}

_token_aud_match if {
	some aud in _token_aud
	aud in _config.allowed_audiences
}

# always convert to array for simpler handling
_token_aud := [_claims.aud] if {
	is_string(_claims.aud)
} else := _claims.aud

_time_now := _config.time if {
	is_number(_config.time)
} else := nanos_to_seconds(time.now_ns())

default _leeway := 0

_leeway := _config.leeway
