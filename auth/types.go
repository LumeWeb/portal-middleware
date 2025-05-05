package auth

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
