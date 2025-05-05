package auth

import (
	"crypto/ed25519"
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/jwt"
)

// ConfigProvider defines an interface for accessing configuration needed by auth middleware
// ConfigProvider defines the configuration requirements for authentication services.
// Implementations should provide cryptographic keys and operational settings.
type ConfigProvider interface {
	GetPrivateKey() ed25519.PrivateKey
	GetDomain() string
	GetAuthCookieName() string
	GetAuthTokenName() string
}

// TokenValidator defines an interface for validating JWT tokens
// TokenValidator handles JWT token validation and claims extraction.
// Implementations should verify token signatures and audience/purpose claims.
type TokenValidator interface {
	Validate(token string, purpose jwt.JWTPurpose) (*gjwt.RegisteredClaims, error)
	ValidateWithClaims(token string, purpose jwt.JWTPurpose) (*gjwt.RegisteredClaims, gjwt.Claims, error)
}

// UserChecker defines an interface for checking user account details
// UserChecker verifies user account status and properties.
// Used by middleware to check account existence and verification status.
type UserChecker interface {
	AccountExists(userID uint) (bool, error)
	IsAccountVerified(userID uint) (bool, error)
}

// AccessChecker determines if a user has access to specific resources.
// Evaluates permissions based on user ID, host, path, and HTTP method.
type AccessChecker interface {
	CheckAccess(userID uint, host string, path string, method string) (bool, error)
}

// ClaimModifier defines a function type for modifying JWT claims
type ClaimModifier func(claims gjwt.Claims)

// JWTOption defines the interface for JWT configuration options
type JWTOption interface {
	Apply(*jwtOptions)
}

type jwtOptions struct {
	claims    gjwt.Claims
	modifiers []ClaimModifier
}

// WithClaimsOpt implements JWTOption to specify custom claims
type WithClaimsOpt struct{ claims gjwt.Claims }
func (o WithClaimsOpt) Apply(opts *jwtOptions) { opts.claims = o.claims }
func WithClaims(c gjwt.Claims) JWTOption       { return WithClaimsOpt{c} }

// WithModifiersOpt implements JWTOption to add claim modifiers
type WithModifiersOpt struct{ modifiers []ClaimModifier }
func (o WithModifiersOpt) Apply(opts *jwtOptions) { opts.modifiers = append(opts.modifiers, o.modifiers...) }
func WithModifiers(m ...ClaimModifier) JWTOption  { return WithModifiersOpt{m} }

// Auth token constants
const (
	AUTH_COOKIE_NAME = "auth_token"
	AUTH_TOKEN_NAME  = "auth_token"
)
