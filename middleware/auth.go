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
func AuthMiddleware(ctx core.Context, purpose jwt.Purpose, options ...AuthOption) echo.MiddlewareFunc {
	config := adapter.NewFromCore(ctx)

	opts := middleware.NewAuthOptions(
		config,
		purpose,
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

// AuthErrorCallback defines a function type that takes a context and returns an error code and JSON serializable response
type AuthErrorCallback = middleware.AuthErrorCallback

// WithAuthErrorCallback sets a custom error callback function for authentication failures
func WithAuthErrorCallback(callback AuthErrorCallback) AuthOption {
	return middleware.WithErrorCallback(callback)
}
