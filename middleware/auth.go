package middleware

import (
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal-middleware/auth/validation"
	"go.lumeweb.com/portal/core"
	"net/http"
)

// AuthMiddleware creates authentication middleware using core configuration
func AuthMiddleware(ctx core.Context, purpose jwt.Purpose, options ...AuthOption) func(http.Handler) http.Handler {
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
type AuthOption func(*middleware.AuthMiddlewareOptions)

// WithEmptyAllowed allows requests without authentication tokens
func WithEmptyAllowed(allow bool) AuthOption {
	return middleware.WithEmptyAllowed(allow)
}

// WithExpiredAllowed allows expired tokens to be processed
func WithExpiredAllowed(allow bool) AuthOption {
	return middleware.WithExpiredAllowed(allow)
}

// WithValidator sets a custom token validator
func WithValidator(validator validation.TokenValidator) AuthOption {
	return middleware.WithValidator(validator)
}
