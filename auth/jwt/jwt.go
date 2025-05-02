package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

// JWTPurpose defines the intended use case for a JWT token within the system.
// This helps prevent token reuse across different application components.
type JWTPurpose string

// VerifyTokenFunc is a callback type for performing custom claim validations.
// Used to add additional security checks beyond standard JWT validation.
type VerifyTokenFunc func(claim *jwt.RegisteredClaims) error

// JWT validation error definitions. These provide specific error types
// for different validation failure scenarios.
var (
	// ErrJWTInvalid indicates general token invalidity (expired, malformed, etc)
	ErrJWTInvalid              = jwt.ErrTokenInvalidClaims
	
	// ErrJWTUnexpectedClaimsType occurs when claims structure doesn't match expectations
	ErrJWTUnexpectedClaimsType = errors.New("unexpected claims type")
	
	// ErrJWTUnexpectedIssuer indicates token was issued by unauthorized authority
	ErrJWTUnexpectedIssuer     = errors.New("unexpected issuer")
)

// Standard JWT purpose constants that define allowed token usages
const (
	JWTPurposeNone  JWTPurpose = ""         // No specific purpose required
	JWTPurposeLogin JWTPurpose = "login"    // Authentication tokens
	JWTPurpose2FA   JWTPurpose = "2fa"      // Two-factor authentication tokens
)
