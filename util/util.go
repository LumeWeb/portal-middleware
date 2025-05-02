// Package util provides HTTP middleware composition and chaining utilities.
// Includes:
// - Middleware chain construction
// - Authentication integration
// - Handler composition patterns
package util

import (
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/cors"
	"go.lumeweb.com/portal/core"
	"net/http"
)

// Middleware provides a chainable wrapper for HTTP handler composition
type Middleware struct {
	handler http.Handler // Wrapped HTTP handler
}

// New creates a new Middleware chain starting with the given handler
func New(h http.Handler) *Middleware {
	return &Middleware{handler: h}
}

// Chain appends multiple middlewares to the handler chain.
// Middlewares are executed in the order they are provided.
func (m *Middleware) Chain(mw func(http.Handler) http.Handler) *Middleware {
	m.handler = mw(m.handler)
	return m
}

func (m *Middleware) Then() http.Handler {
	return m.handler
}

// WithAuth adds authentication middleware using a ConfigProvider
// WithAuth adds authentication middleware to the chain.
// Configures JWT validation with the specified purpose and configuration.
func (m *Middleware) WithAuth(config auth.ConfigProvider, purpose string) *Middleware {
	return m.Chain(auth.AuthMiddleware(auth.AuthMiddlewareOptions{
		Config:         config,
		Purpose:        purpose,
		ExpiredAllowed: false,
	}))
}

// WithAuthFromCore adds authentication middleware using core.Context
func (m *Middleware) WithAuthFromCore(ctx core.Context, purpose string) *Middleware {
	return m.WithAuth(adapter.NewFromCore(ctx), purpose)
}

func (m *Middleware) WithCORS(config cors.Config) *Middleware {
	return m.Chain(cors.New(config))
}
