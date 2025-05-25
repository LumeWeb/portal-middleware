package middleware

import (
	"github.com/gorilla/mux"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/middleware"
	"go.lumeweb.com/portal/core"
)

func WithVerification(ctx core.Context) httputil.RouteOption {
	return func(d *httputil.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AccountVerifiedMiddleware(ctx))
	}
}

func With2FA(ctx core.Context) httputil.RouteOption {
	return func(d *httputil.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, middleware.AuthMiddleware(ctx, jwt.Purpose2FA))
	}
}

// Middleware option
func WithMiddleware(mw ...mux.MiddlewareFunc) httputil.RouteOption {
	return func(d *httputil.RouteDefinition) {
		d.Middlewares = append(d.Middlewares, mw...)
	}
}
