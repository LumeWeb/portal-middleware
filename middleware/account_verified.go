package middleware

import (
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"net/http"

	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal/core"
)

// AccountVerifiedMiddleware creates middleware that checks if a user account is verified
// using the core.UserService from the provided context.
func AccountVerifiedMiddleware(ctx core.Context) func(http.Handler) http.Handler {
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	return middleware.AccountVerified(userChecker)
}
