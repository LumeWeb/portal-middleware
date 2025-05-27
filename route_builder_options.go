package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
)

func WithVerification(ctx core.Context) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AccountVerifiedMiddleware(ctx))
	}
}

func With2FA(ctx core.Context) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AuthMiddleware(ctx, jwt.Purpose2FA))
	}
}

// Middleware option
func WithMiddleware(mw ...echo.MiddlewareFunc) router.RouteOption {
	return func(d *router.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, mw...)
	}
}
