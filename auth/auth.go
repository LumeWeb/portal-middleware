package auth

import (
	"context"
	"crypto/ed25519"
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/context"
	"net/http"
	"strconv"
	"strings"
)

// ParseAuthTokenHeader extracts a JWT token from the Authorization header.
// It supports both "Bearer" and "bearer" prefixes, returning the token string
// without any prefix. Returns empty string if no valid Authorization header is found.
func ParseAuthTokenHeader(headers http.Header) string {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	authHeader = strings.TrimPrefix(authHeader, "bearer ")

	return authHeader
}

// IsValidJWT checks if a JWT token is valid and properly signed.
// Verifies the token signature using the provided Ed25519 private key's public key.
// Returns true only if the token is properly formatted and signed.
func IsValidJWT(tokenString string, secretKey ed25519.PrivateKey) bool {
	var claims gjwt.RegisteredClaims
	token, err := gjwt.ParseWithClaims(tokenString, &claims, func(token *gjwt.Token) (interface{}, error) {
		return secretKey.Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))

	if err != nil {
		return false
	}

	return token.Valid
}

// AuthMiddlewareOptions configures the authentication middleware behavior.
// Contains settings for token validation, purpose restrictions, and error handling.
type AuthMiddlewareOptions struct {
	Config         ConfigProvider
	Validator      TokenValidator
	Purpose        jwt.JWTPurpose
	EmptyAllowed   bool
	ExpiredAllowed bool
}

// AuthMiddleware creates HTTP middleware for JWT authentication.
// Validates tokens according to the provided options and injects user context.
// Handles token validation errors and expired tokens according to configuration.
// Returns a handler that can be chained with other middleware.
func AuthMiddleware(options AuthMiddlewareOptions) func(http.Handler) http.Handler {
	if options.Config == nil {
		panic("AuthMiddleware requires a ConfigProvider")
	}
	if options.Purpose == "" {
		panic("AuthMiddleware requires a Purpose")
	}

	findToken := func(r *http.Request) string {
		return FindAuthToken(r, options.Config.GetPrivateKey(),
			options.Config.GetDomain(), options.Config.GetAuthCookieName(), options.Config.GetAuthTokenName())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authToken := findToken(r)
			if authToken == "" {
				if !options.EmptyAllowed {
					http.Error(w, "Invalid JWT", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			validator := options.Validator
			if validator == nil {
				validator = &jwtValidator{config: options.Config}
			}

			// Get both base and custom claims
			baseClaims, customClaims, err := validator.ValidateWithClaims(authToken, options.Purpose)
			if err != nil {
				// Handle expired token case when allowed
				if options.ExpiredAllowed && err == gjwt.ErrTokenExpired {
					// We still need to have baseClaims to proceed
					if baseClaims == nil {
						http.Error(w, "Invalid JWT", http.StatusUnauthorized)
						return
					}
				} else {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
			}

			// Build context with all claims
			ctx := r.Context()
			if baseClaims != nil {
				userID, _ := strconv.ParseUint(baseClaims.Subject, 10, 64)
				ctx = context.WithValue(ctx, mcontext.UserIDKey, uint(userID))
				ctx = context.WithValue(ctx, mcontext.AuthTokenKey, authToken)

				// Store claims in unified wrapper
				wrapper := &claimsWrapper{
					Base:   baseClaims,
					Custom: customClaims,
				}
				ctx = context.WithValue(ctx, claimsContextKey{}, wrapper)
			}
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

func FindAuthToken(r *http.Request, secretKey ed25519.PrivateKey, domain string, cookieName string, queryParam string) string {
	// Check Authorization header first
	if token := ParseAuthTokenHeader(r.Header); token != "" {
		if IsValidJWT(token, secretKey) {
			return token
		}
	}

	// Check primary cookie
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		if IsValidJWT(cookie.Value, secretKey) {
			return cookie.Value
		}
	}

	// Check fallback cookie
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		if IsValidJWT(cookie.Value, secretKey) {
			return cookie.Value
		}
	}

	// Check query param last
	if token := r.FormValue(queryParam); token != "" {
		if IsValidJWT(token, secretKey) {
			return token
		}
	}

	// Return first non-valid token found
	if token := ParseAuthTokenHeader(r.Header); token != "" {
		return token
	}
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		return cookie.Value
	}
	if cookie, err := r.Cookie(cookieName); err == nil && cookie != nil {
		return cookie.Value
	}
	if token := r.FormValue(queryParam); token != "" {
		return token
	}

	return ""
}

type jwtValidator struct {
	config ConfigProvider
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ TokenValidator = (*jwtValidator)(nil)
)

var nopVerifyFunc jwt.VerifyTokenFunc = func(claim *gjwt.RegisteredClaims) error {
	return nil
}

func (v *jwtValidator) Validate(token string, purpose jwt.JWTPurpose) (*gjwt.RegisteredClaims, error) {
	claims, _, err := v.ValidateWithClaims(token, purpose)
	return claims, err
}

func (v *jwtValidator) ValidateWithClaims(token string, purpose jwt.JWTPurpose) (*gjwt.RegisteredClaims, gjwt.Claims, error) {
	domain := v.config.GetDomain()

	// Default to RegisteredClaims
	claims := &gjwt.RegisteredClaims{}

	tokenObj, err := gjwt.ParseWithClaims(token, claims, func(token *gjwt.Token) (interface{}, error) {
		return v.config.GetPrivateKey().Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))

	if err != nil {
		return nil, nil, err
	}

	if !tokenObj.Valid {
		return nil, nil, jwt.ErrJWTInvalid
	}

	baseClaims, ok := tokenObj.Claims.(*gjwt.RegisteredClaims)
	if !ok {
		return nil, nil, jwt.ErrJWTUnexpectedClaimsType
	}

	// Validate audience/purpose
	aud, _ := baseClaims.GetAudience()
	if purpose != jwt.JWTPurposeNone && !JWTPurposeEqual(aud, purpose) {
		return nil, nil, jwt.ErrJWTInvalid
	}

	// Validate issuer
	if baseClaims.Issuer != domain {
		return nil, nil, jwt.ErrJWTUnexpectedIssuer
	}

	return baseClaims, tokenObj.Claims, nil
}

func NewValidator(config ConfigProvider) TokenValidator {
	return &jwtValidator{config: config}
}

func JWTPurposeEqual(aud gjwt.ClaimStrings, purpose jwt.JWTPurpose) bool {
	for _, a := range aud {
		if a == string(purpose) {
			return true
		}
	}
	return false
}

// claimsContextKey is used to store all claims in context
type claimsContextKey struct{}

// claimsWrapper contains both base and custom claims
type claimsWrapper struct {
	Base   *gjwt.RegisteredClaims
	Custom gjwt.Claims
}

// GetClaims retrieves claims from context
func GetClaims[T gjwt.Claims](ctx context.Context) (T, bool) {
	val := ctx.Value(claimsContextKey{})
	if val == nil {
		var zero T
		return zero, false
	}

	wrapper, ok := val.(*claimsWrapper)
	if !ok {
		var zero T
		return zero, false
	}

	claims, ok := wrapper.Custom.(T)
	return claims, ok
}

// JWTVerifyToken verifies a JWT token
func JWTVerifyToken(tokenString string, domain string, privateKey ed25519.PrivateKey,
	claimCheck jwt.VerifyTokenFunc) (*gjwt.RegisteredClaims, error) {

	if claimCheck == nil {
		claimCheck = nopVerifyFunc
	}

	var claims gjwt.RegisteredClaims

	token, err := gjwt.ParseWithClaims(tokenString, &claims, func(token *gjwt.Token) (interface{}, error) {
		return privateKey.Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrJWTInvalid
	}

	if err := claimCheck(&claims); err != nil {
		return nil, err
	}

	if claims.Issuer != domain {
		return nil, jwt.ErrJWTUnexpectedIssuer
	}

	return &claims, nil
}
