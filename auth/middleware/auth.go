package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"reflect"
	"strconv"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/validation"
	mcontext "go.lumeweb.com/portal-middleware/context"
)

// AuthErrorCallback defines a function type that takes a context and returns an error code and JSON serializable response
type AuthErrorCallback func(c echo.Context) (int, json.Marshaler)

// AuthMiddlewareOption defines a functional option for configuring AuthMiddlewareOptions.
// It modifies the settings or behavior of AuthMiddlewareOptions during initialization.
type AuthMiddlewareOption = func(*AuthMiddlewareOptions)

// AuthMiddlewareOptions configures the authentication middleware behavior.
// Contains settings for token validation, purpose restrictions, and error handling.
type AuthMiddlewareOptions struct {
	Config         adapter.ConfigProvider
	Validator      validation.TokenValidator
	Purposes       []jwt.Purpose
	EmptyAllowed   bool
	ExpiredAllowed bool
	Options        []jwt.Option
	ExpectedClaims gjwt.Claims
	ErrorCallback  AuthErrorCallback
	KeyLoggers     []auth.JWTKeyLogger
}

// handleError processes authentication errors using the custom error callback if provided,
// otherwise returns the default echo.ErrUnauthorized
func (options *AuthMiddlewareOptions) handleError(c echo.Context) error {
	if options.ErrorCallback != nil {
		code, response := options.ErrorCallback(c)
		return c.JSON(code, response)
	}
	return echo.ErrUnauthorized
}

// logTokenAccess notifies every registered JWTKeyLogger that a token was
// processed. A faulty plugin logger must never fail the request, so panics
// raised inside RecordAccess are recovered and discarded.
func (options *AuthMiddlewareOptions) logTokenAccess(c echo.Context, token string, purpose jwt.Purpose, claims gjwt.Claims, err error) {
	for _, logger := range options.KeyLoggers {
		if logger == nil {
			continue
		}
		func() {
			defer func() { _ = recover() }()
			logger.RecordAccess(c, token, purpose, claims, err)
		}()
	}
}

// AuthMiddleware creates Echo middleware for JWT authentication
// Validates tokens and injects user context if valid
func AuthMiddleware(options AuthMiddlewareOptions) echo.MiddlewareFunc {
	if options.Config == nil {
		panic("AuthMiddleware requires a ConfigProvider")
	}
	if len(options.Purposes) == 0 {
		panic("AuthMiddleware requires at least one Purpose")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			authToken := auth.FindAuthToken(r, options.Config.GetPrivateKey(), options.Config.GetAuthCookieName(), options.Config.GetAuthTokenName())
			if authToken == "" {
				if !options.EmptyAllowed {
					return options.handleError(c)
				}
				return next(c)
			}

			validator := options.Validator
			if validator == nil {
				validator = validation.NewValidator(options.Config)
			}

			// Determine claims type to validate against
			claimsType := options.ExpectedClaims
			if claimsType == nil {
				claimsType = &gjwt.RegisteredClaims{}
			}

			var baseClaims *gjwt.RegisteredClaims
			var customClaims gjwt.Claims
			var err error
			// Track earliest expired match so we can honor ExpiredAllowed
			var expiredBase *gjwt.RegisteredClaims
			var expiredCustom gjwt.Claims
			var sawExpired bool
			// Purpose used for key logging: the successful purpose, or the last
			// attempted one when all purposes failed.
			var loggedPurpose jwt.Purpose

			for _, purpose := range options.Purposes {
				loggedPurpose = purpose
				bc, cc, e := validator.ValidateWithClaims(authToken, purpose, claimsType)
				if e == nil {
					baseClaims, customClaims, err = bc, cc, nil
					break
				}
				// Remember an expired match
				if options.ExpiredAllowed && errors.Is(e, gjwt.ErrTokenExpired) {
					if bc != nil {
						expiredBase, expiredCustom = bc, cc
						sawExpired = true
					}
				}
				err = e
			}
			if err != nil {
				if sawExpired && expiredBase != nil {
					baseClaims, customClaims = expiredBase, expiredCustom
				} else {
					options.logTokenAccess(c, authToken, loggedPurpose, nil, err)
					return options.handleError(c)
				}
			}

			// If validation passed but we got nil claims, reject
			if baseClaims == nil {
				options.logTokenAccess(c, authToken, loggedPurpose, nil,
					fmt.Errorf("validation passed but claims are nil: %w", jwt.ErrJWTInvalid))
				return options.handleError(c)
			}

			// If we got claims but they don't match expected type, reject
			if customClaims != nil && !reflect.TypeOf(customClaims).AssignableTo(reflect.TypeOf(claimsType)) {
				options.logTokenAccess(c, authToken, loggedPurpose, customClaims,
					fmt.Errorf("claims type mismatch: %T: %w", customClaims, jwt.ErrJWTUnexpectedClaimsType))
				return options.handleError(c)
			}

			// Build context with all claims
			if baseClaims != nil {
				userID, err := strconv.ParseUint(baseClaims.Subject, 10, 64)
				if err != nil {
					options.logTokenAccess(c, authToken, loggedPurpose, baseClaims, err)
					return options.handleError(c)
				}
				c.Set(string(mcontext.UserIDKey), uint(userID))
				c.Set(string(mcontext.AuthTokenKey), authToken)

				// Only store custom claims if they match the expected type
				if customClaims != nil {
					claimsType := jwt.GetClaimsType(options.Options)
					expectedClaimsType := reflect.TypeOf(claimsType).Elem()

					if expectedClaimsType != nil {
						actualType := reflect.TypeOf(customClaims)
						expectedPtrType := reflect.PointerTo(expectedClaimsType)

						// Check if types match directly or via pointer
						if !actualType.AssignableTo(expectedClaimsType) &&
							!actualType.AssignableTo(expectedPtrType) {
							options.logTokenAccess(c, authToken, loggedPurpose, customClaims,
								fmt.Errorf("claims type mismatch: %T: %w", customClaims, jwt.ErrJWTUnexpectedClaimsType))
							return options.handleError(c)
						}
					}
					// Store claims in context
					wrapper := auth.NewClaimsWrapper(baseClaims, customClaims)
					c.Set(string(mcontext.ClaimsContextKey), wrapper)

					// Also set in request context for compatibility
					req := c.Request()
					ctx := context.WithValue(req.Context(), mcontext.ClaimsContextKey, wrapper)
					c.SetRequest(req.WithContext(ctx))
				} else {
					// Store just base claims if no custom claims
					wrapper := auth.NewClaimsWrapper(baseClaims, nil)
					c.Set(string(mcontext.ClaimsContextKey), wrapper)

					// Also set in request context for compatibility
					req := c.Request()
					ctx := context.WithValue(req.Context(), mcontext.ClaimsContextKey, wrapper)
					c.SetRequest(req.WithContext(ctx))
				}
			}

			options.logTokenAccess(c, authToken, loggedPurpose, baseClaims, nil)
			return next(c)
		}
	}
}

// NewAuthOptions creates and configures AuthMiddlewareOptions in one step
func NewAuthOptions(config adapter.ConfigProvider, opts ...AuthMiddlewareOption) *AuthMiddlewareOptions {
	options := &AuthMiddlewareOptions{
		Config:         config,
		Purposes:       nil,   // must be set via WithPurpose
		EmptyAllowed:   false, // default
		ExpiredAllowed: false, // default
		ErrorCallback:  nil,   // default
	}

	for _, opt := range opts {
		opt(options)
	}
	return options
}

// WithConfig sets the ConfigProvider for the options
func WithConfig(config adapter.ConfigProvider) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.Config = config
	}
}

// WithPurpose sets the JWT purposes for the options
func WithPurpose(purposes ...jwt.Purpose) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		clean := lo.Uniq(lo.Filter(purposes, func(p jwt.Purpose, _ int) bool {
			return p != ""
		}))
		if len(clean) == 0 {
			panic("WithPurpose requires at least one non-empty purpose")
		}
		opts.Purposes = clean
	}
}

// WithValidator sets a custom token validator
func WithValidator(validator validation.TokenValidator) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.Validator = validator
	}
}

// WithEmptyAllowed configures whether empty tokens are allowed
func WithEmptyAllowed(allow bool) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.EmptyAllowed = allow
	}
}

// WithExpiredAllowed configures whether expired tokens are allowed
func WithExpiredAllowed(allow bool) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.ExpiredAllowed = allow
	}
}

// WithJWTOptions adds JWT-specific options
func WithJWTOptions(jwtOpts ...jwt.Option) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.Options = append(opts.Options, jwtOpts...)
		// Find and store the claims type if present
		for _, opt := range jwtOpts {
			if claimOpt, ok := opt.(jwt.WithClaimsOpt); ok {
				opts.ExpectedClaims = claimOpt.Claims()
				break
			}
		}
	}
}

// WithErrorCallback sets a custom error callback function
func WithErrorCallback(callback AuthErrorCallback) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.ErrorCallback = callback
	}
}

// WithKeyLogger registers JWT key loggers that get notified whenever the
// middleware processes a token, so plugins can record JWT access.
func WithKeyLogger(loggers ...auth.JWTKeyLogger) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.KeyLoggers = append(opts.KeyLoggers, loggers...)
	}
}
