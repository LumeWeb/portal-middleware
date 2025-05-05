package middleware

import (
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal/core"
	"net/http"
)

// NewAccessMiddlewareFromCore creates an AccessMiddleware using services from core.Context
func NewAccessMiddlewareFromCore(ctx core.Context) func(http.Handler) http.Handler {
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	accessChecker := adapter.NewAccessCheckerFromCore(ctx)
	return AccessMiddleware(userChecker, accessChecker)
}
