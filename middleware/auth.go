package middleware

import (
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/middleware"
	"go.lumeweb.com/portal/core"
)

// AuthMiddleware creates authentication middleware using core configuration
func AuthMiddleware(ctx core.Context, purpose string, options ...middleware.AuthOption) func(http.Handler) http.Handler {
	config := adapter.NewFromCore(ctx)
	
	opts := middleware.NewAuthOptions(
		middleware.WithConfig(config),
		middleware.WithPurpose(purpose),
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
	return func(opts *middleware.AuthMiddlewareOptions) {
		opts.EmptyAllowed = allow
	}
}

// WithExpiredAllowed allows expired tokens to be processed
func WithExpiredAllowed(allow bool) AuthOption {
	return func(opts *middleware.AuthMiddlewareOptions) {
		opts.ExpiredAllowed = allow
	}
}

// WithValidator sets a custom token validator
func WithValidator(validator middleware.TokenValidator) AuthOption {
	return func(opts *middleware.AuthMiddlewareOptions) {
		opts.Validator = validator
	}
}
