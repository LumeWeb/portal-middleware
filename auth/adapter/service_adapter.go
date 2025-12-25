package adapter

import (
	"context"

	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal/core"
)

// coreUserChecker adapts the core framework's UserService to implement auth.UserChecker.
// Enables the auth package to use core user services without direct dependency.
type coreUserChecker struct {
	userService core.UserService
}

// coreAccessChecker adapts the core framework's AccessService to implement auth.AccessChecker.
// Bridges the gap between core access control system and auth middleware requirements.
type coreAccessChecker struct {
	accessService core.AccessService
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ auth.UserChecker   = (*coreUserChecker)(nil)
	_ auth.AccessChecker = (*coreAccessChecker)(nil)
)

// AccountExists checks if a user account exists in the core user directory.
// Implements auth.UserChecker interface by delegating to core.UserService.
// Returns:
// - bool: True if account exists
// - error: Any error encountered during the check
func (c *coreUserChecker) AccountExists(ctx context.Context, userID uint) (bool, error) {
	exists, _, err := c.userService.AccountExists(userID)
	return exists, err
}

// IsAccountVerified checks if the user has completed required verification steps.
// Used to enforce account verification before granting access to protected resources.
// Returns:
// - bool: True if account is fully verified
// - error: Any error encountered during verification check
func (c *coreUserChecker) IsAccountVerified(ctx context.Context, userID uint) (bool, error) {
	return c.userService.IsAccountVerified(userID)
}

// CheckAccess verifies if a user is authorized to access a specific resource.
// Implements auth.AccessChecker interface using core access control rules.
// Parameters:
// - userID: Subject of the access check
// - host: Target domain/hostname
// - path: Request path being accessed
// - method: HTTP method being used
// Returns:
// - bool: True if access is granted
// - error: Any error encountered during access check
func (c *coreAccessChecker) CheckAccess(ctx context.Context, userID uint, host string, path string, method string) (bool, error) {
	return c.accessService.CheckAccess(userID, host, path, method)
}

// NewUserChecker creates a new UserChecker from core.UserService
func NewUserChecker(userService core.UserService) auth.UserChecker {
	return &coreUserChecker{
		userService: userService,
	}
}

// NewAccessChecker creates a new AccessChecker from core.AccessService
func NewAccessChecker(accessService core.AccessService) auth.AccessChecker {
	return &coreAccessChecker{
		accessService: accessService,
	}
}

// NewUserCheckerFromCore creates a UserChecker instance backed by core framework's UserService.
// Typical usage:
//
//	ctx := core.GetContext()
//	checker := adapter.NewUserCheckerFromCore(ctx)
func NewUserCheckerFromCore(ctx core.Context) auth.UserChecker {
	userService := core.GetService[core.UserService](ctx, core.USER_SERVICE)

	return NewUserChecker(userService)
}

// NewAccessCheckerFromCore creates a new AccessChecker from core.Context
func NewAccessCheckerFromCore(ctx core.Context) auth.AccessChecker {
	accessService := core.GetService[core.AccessService](ctx, core.ACCESS_SERVICE)

	return NewAccessChecker(accessService)
}
