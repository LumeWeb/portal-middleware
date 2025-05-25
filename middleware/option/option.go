package option

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
)

func WithVerification(ctx core.Context) router.RouteOption {
	if ctx == nil {
		panic("WithVerification requires a non-nil core.Context")
	}

	// Verify UserService exists early to fail fast
	if ctx.Service(core.USER_SERVICE) == nil {
		panic("WithVerification requires core.USER_SERVICE to be registered in context")
	}

	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AccountVerifiedMiddleware(ctx))
	}
}

func With2FA(ctx core.Context) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AuthMiddleware(ctx, jwt.Purpose2FA))
	}
}

func WithAuth(ctx core.Context) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AuthMiddleware(ctx, jwt.PurposeLogin))
	}
}

// Middleware option
func WithMiddleware(mw ...echo.MiddlewareFunc) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, mw...)
	}
}
