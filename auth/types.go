package auth

import (
	"crypto/ed25519"
	"github.com/golang-jwt/jwt/v5"
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
	Validate(token string, purpose string) (*jwt.RegisteredClaims, error)
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

// Auth token constants
const (
	AUTH_COOKIE_NAME = "auth_token"
	AUTH_TOKEN_NAME  = "auth_token"
)
