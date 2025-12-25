package auth

import "context"

// UserChecker defines an interface for checking user account details
// UserChecker verifies user account status and properties.
// Used by middleware to check account existence and verification status.
type UserChecker interface {
	AccountExists(ctx context.Context, userID uint) (bool, error)
	IsAccountVerified(ctx context.Context, userID uint) (bool, error)
}

// AccessChecker determines if a user has access to specific resources.
// Evaluates permissions based on user ID, host, path, and HTTP method.
type AccessChecker interface {
	CheckAccess(ctx context.Context, userID uint, host string, path string, method string) (bool, error)
}
