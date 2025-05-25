package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal/core"
)

// AccountVerifiedMiddleware creates middleware that checks if a user account is verified
// using the core.UserService from the provided context.
func AccountVerifiedMiddleware(ctx core.Context) echo.MiddlewareFunc {
	if ctx == nil {
		panic("AccountVerifiedMiddleware requires a non-nil core.Context")
	}
	
	userService := ctx.Service(core.USER_SERVICE)
	if userService == nil {
		panic("AccountVerifiedMiddleware requires core.USER_SERVICE to be registered in context")
	}
	
	userChecker := adapter.NewUserCheckerFromCore(ctx)
	return middleware.AccountVerified(userChecker)
}
