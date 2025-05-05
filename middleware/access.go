package middleware

import (
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"net/http"

	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal/core"
)

// AccessMiddleware creates middleware for checking access permissions using core services
func AccessMiddleware(ctx core.Context) func(http.Handler) http.Handler {
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	accessChecker := adapter.NewAccessCheckerFromCore(ctx)

	return middleware.AccessMiddleware(userChecker, accessChecker)
}
