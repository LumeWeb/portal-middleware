package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal/core"
)

// NewAccessMiddlewareFromCore creates an AccessMiddleware using services from core.Context
func NewAccessMiddlewareFromCore(ctx core.Context) echo.MiddlewareFunc {
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	accessChecker := adapter.NewAccessCheckerFromCore(ctx)
	return AccessMiddleware(userChecker, accessChecker)
}
