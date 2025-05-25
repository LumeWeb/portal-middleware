package middleware

import (
	"context"
	"errors"
	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/validation"
	mcontext "go.lumeweb.com/portal-middleware/context"
	"reflect"
	"strconv"
)

// AuthMiddlewareOption defines a functional option for configuring AuthMiddlewareOptions.
// It modifies the settings or behavior of AuthMiddlewareOptions during initialization.
type AuthMiddlewareOption = func(*AuthMiddlewareOptions)

// AuthMiddlewareOptions configures the authentication middleware behavior.
// Contains settings for token validation, purpose restrictions, and error handling.
// This struct is defined in auth/types.go to avoid duplication
type AuthMiddlewareOptions struct {
	Config         adapter.ConfigProvider
	Validator      validation.TokenValidator
	Purpose        jwt.Purpose
	EmptyAllowed   bool
	ExpiredAllowed bool
	Options        []jwt.Option
	ExpectedClaims gjwt.Claims
}

// AuthMiddleware creates Echo middleware for JWT authentication
// Validates tokens and injects user context if valid
func AuthMiddleware(options AuthMiddlewareOptions) echo.MiddlewareFunc {
	if options.Config == nil {
		panic("AuthMiddleware requires a ConfigProvider")
	}
	if options.Purpose == "" {
		panic("AuthMiddleware requires a Purpose")
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			authToken := auth.FindAuthToken(r, options.Config.GetPrivateKey(), options.Config.GetAuthCookieName(), options.Config.GetAuthTokenName())
			if authToken == "" {
				if !options.EmptyAllowed {
					return echo.ErrUnauthorized
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

			baseClaims, customClaims, err := validator.ValidateWithClaims(authToken, options.Purpose, claimsType)
			if err != nil {
				// Handle expired tokens when allowed
				if options.ExpiredAllowed && errors.Is(err, gjwt.ErrTokenExpired) {
					// We still need baseClaims to proceed
					if baseClaims == nil {
						return echo.ErrUnauthorized
					}
				} else {
					return echo.ErrUnauthorized
				}
			}

			// If validation passed but we got nil claims, reject
			if baseClaims == nil {
				return echo.ErrUnauthorized
			}

			// If we got claims but they don't match expected type, reject
			if customClaims != nil && !reflect.TypeOf(customClaims).AssignableTo(reflect.TypeOf(claimsType)) {
				return echo.ErrUnauthorized
			}

			// Build context with all claims
			if baseClaims != nil {
				userID, err := strconv.ParseUint(baseClaims.Subject, 10, 64)
				if err != nil {
					return echo.ErrUnauthorized
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
							return echo.ErrUnauthorized
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

			return next(c)
		}
	}
}

// NewAuthOptions creates and configures AuthMiddlewareOptions in one step
func NewAuthOptions(config adapter.ConfigProvider, purpose jwt.Purpose, opts ...AuthMiddlewareOption) *AuthMiddlewareOptions {
	options := &AuthMiddlewareOptions{
		Config:         config,
		Purpose:        purpose,
		EmptyAllowed:   false, // default
		ExpiredAllowed: false, // default
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

// WithPurpose sets the JWT purpose for the options
func WithPurpose(purpose jwt.Purpose) AuthMiddlewareOption {
	return func(opts *AuthMiddlewareOptions) {
		opts.Purpose = purpose
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
