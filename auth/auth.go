package auth

import (
	"context"
	"crypto/ed25519"
	gjwt "github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

// ParseAuthToken extracts a JWT token from the Authorization header
// Returns the token string or empty if not found
func ParseAuthToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	authHeader = strings.TrimPrefix(authHeader, "bearer ")
	return authHeader
}

// ParseAuthTokenHeader extracts a JWT token from the Authorization header.
// It supports both "Bearer" and "bearer" prefixes, returning the token string
// without any prefix. Returns empty string if no valid Authorization header is found.
func ParseAuthTokenHeader(headers http.Header) string {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	authHeader = strings.TrimPrefix(authHeader, "bearer ")

	return authHeader
}

// IsValidJWT checks if a JWT token is valid and properly signed.
// Verifies the token signature using the provided Ed25519 private key's public key.
// Returns true only if the token is properly formatted and signed.
func IsValidJWT(tokenString string, secretKey ed25519.PrivateKey) bool {
	var claims gjwt.RegisteredClaims
	token, err := gjwt.ParseWithClaims(tokenString, &claims, func(token *gjwt.Token) (interface{}, error) {
		return secretKey.Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))

	if err != nil {
		return false
	}

	return token.Valid
}

func FindAuthToken(r *http.Request, secretKey ed25519.PrivateKey, domain string, cookieName string, queryParam string) string {
	// Check Authorization header first
	if token := ParseAuthTokenHeader(r.Header); token != "" {
		if IsValidJWT(token, secretKey) {
			return token
		}
	}

	// Check primary cookie
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		if IsValidJWT(cookie.Value, secretKey) {
			return cookie.Value
		}
	}

	// Check fallback cookie
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		if IsValidJWT(cookie.Value, secretKey) {
			return cookie.Value
		}
	}

	// Check query param last
	if token := r.FormValue(queryParam); token != "" {
		if IsValidJWT(token, secretKey) {
			return token
		}
	}

	// Return first non-valid token found
	if token := ParseAuthTokenHeader(r.Header); token != "" {
		return token
	}
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		return cookie.Value
	}
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		return cookie.Value
	}
	if token := r.FormValue(queryParam); token != "" {
		return token
	}

	return ""
}

// claimsContextKey is used to store claims in request context
type ClaimsContextKey struct{}

// claimsWrapper contains both base and custom claims
type claimsWrapper struct {
	Base   *gjwt.RegisteredClaims
	Custom gjwt.Claims
}

func NewClaimsWrapper(base *gjwt.RegisteredClaims, custom gjwt.Claims) *claimsWrapper {
	return &claimsWrapper{
		Base:   base,
		Custom: custom,
	}
}

// GetClaims retrieves claims from context by type
func GetClaims[T gjwt.Claims](ctx context.Context) (T, bool) {
	var zero T

	val := ctx.Value(ClaimsContextKey{})
	if val == nil {
		return zero, false
	}

	wrapper, ok := val.(*claimsWrapper)
	if !ok {
		return zero, false
	}

	// Handle base claims request
	switch any(zero).(type) {
	case *gjwt.RegisteredClaims:
		if wrapper.Base == nil {
			return zero, false
		}
		// Safe to cast since we checked the type
		return any(wrapper.Base).(T), true
	default:
		// Handle custom claims
		if wrapper.Custom == nil {
			return zero, false
		}

		claims, ok := wrapper.Custom.(T)
		if !ok {
			return zero, false
		}

		return claims, true
	}
}
