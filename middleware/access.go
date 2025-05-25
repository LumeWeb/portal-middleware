package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal/core"
)

// AccessMiddleware creates middleware for checking access permissions using core services
func AccessMiddleware(ctx core.Context) echo.MiddlewareFunc {
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	accessChecker := adapter.NewAccessCheckerFromCore(ctx)

	return middleware.AccessMiddleware(userChecker, accessChecker)
}
