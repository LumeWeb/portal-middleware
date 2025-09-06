package middleware

import (
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal-middleware/auth/validation"
	"go.lumeweb.com/portal/core"
)

// AuthMiddleware creates authentication middleware using core configuration
func AuthMiddleware(ctx core.Context, purposes []jwt.Purpose, options ...AuthOption) echo.MiddlewareFunc {
	config := adapter.NewFromCore(ctx)

	opts := middleware.NewAuthOptions(
		config,
		purposes,
	)

	for _, option := range options {
		option(opts)
	}

	return middleware.AuthMiddleware(*opts)
}

// AuthOption configures the authentication middleware
type AuthOption = middleware.AuthMiddlewareOption

// WithAuthEmptyAllowed allows requests without authentication tokens
func WithAuthEmptyAllowed(allow bool) AuthOption {
	return middleware.WithEmptyAllowed(allow)
}

// WithAuthExpiredAllowed allows expired tokens to be processed
func WithAuthExpiredAllowed(allow bool) AuthOption {
	return middleware.WithExpiredAllowed(allow)
}

// WithAuthValidator sets a custom token validator
func WithAuthValidator(validator validation.TokenValidator) AuthOption {
	return middleware.WithValidator(validator)
}

// WithAuthJWTOptions applies custom JWT options to the authentication middleware configuration.
func WithAuthJWTOptions(jwtOpts ...jwt.Option) AuthOption {
	return middleware.WithJWTOptions(jwtOpts...)
}

// WithAuthPurpose forwards to middleware.WithPurpose for configuring allowed JWT purposes
func WithAuthPurpose(purposes ...jwt.Purpose) AuthOption {
	return middleware.WithPurpose(purposes...)
}

// AuthMiddlewareSinglePurpose is a convenience wrapper for AuthMiddleware that accepts a single purpose
func AuthMiddlewareSinglePurpose(ctx core.Context, purpose jwt.Purpose, options ...AuthOption) echo.MiddlewareFunc {
	return AuthMiddleware(ctx, []jwt.Purpose{purpose}, options...)
}

// AuthErrorCallback defines a function type that takes a context and returns an error code and JSON serializable response
type AuthErrorCallback = middleware.AuthErrorCallback

// WithAuthErrorCallback sets a custom error callback function for authentication failures
func WithAuthErrorCallback(callback AuthErrorCallback) AuthOption {
	return middleware.WithErrorCallback(callback)
}
