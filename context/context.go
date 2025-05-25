// Package mcontext provides standardized context keys and accessors
// for common authentication values used across middleware components.
//
// This package defines type-safe context keys and validation functions
// to ensure consistent handling of user identity and authentication tokens
// throughout the request lifecycle.
package mcontext

import (
	"errors"
	"github.com/labstack/echo/v4"
)

// Key represents a type-safe context key for storing request-scoped values.
// Using a dedicated type prevents namespace collisions between packages.
type Key string

const (
	// UserIDKey is the context key for storing authenticated user IDs (uint type).
	// Use with context.WithValue and GetUserID for type-safe access.
	UserIDKey Key = "userID"

	// AuthTokenKey is the context key for storing validated authentication tokens.
	// Use with context.WithValue and GetAuthToken for type-safe access.
	AuthTokenKey Key = "authToken"

	// ClaimsContextKey is the context key for storing JWT claims
	ClaimsContextKey Key = "jwtClaims"
)

var (
	// ErrUserContextInvalid occurs when a context value exists for UserIDKey
	// but is not of type uint. Typically indicates improper context population.
	ErrUserContextInvalid = errors.New("user id stored in context is not of type uint")

	// ErrAuthTokenContextInvalid occurs when a context value exists for AuthTokenKey
	// but is not of type string. Indicates invalid token storage.
	ErrAuthTokenContextInvalid = errors.New("auth token stored in context is not of type string")
)

// GetUserID retrieves a user ID from the echo context. Validates that:
// 1. A value exists for UserIDKey
// 2. The value is of type uint
//
// Returns:
//   - uint: The authenticated user ID
//   - error: ErrUserContextInvalid if value is missing or invalid type
func GetUserID(c echo.Context) (uint, error) {
	userID, ok := c.Get(string(UserIDKey)).(uint)
	if !ok {
		return 0, ErrUserContextInvalid
	}
	return userID, nil
}

// GetAuthToken retrieves an authentication token from the echo context.
// Validates that any existing AuthTokenKey value is a string.
//
// Returns:
//   - string: The raw authentication token
//   - error: ErrAuthTokenContextInvalid if type assertion fails
func GetAuthToken(c echo.Context) (string, error) {
	authToken, ok := c.Get(string(AuthTokenKey)).(string)
	if !ok {
		return "", ErrAuthTokenContextInvalid
	}
	return authToken, nil
}
