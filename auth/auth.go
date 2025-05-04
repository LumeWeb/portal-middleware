package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"go.lumeweb.com/portal-middleware/context"
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
	Purpose        string
	EmptyAllowed   bool
	ExpiredAllowed bool
}

// AuthMiddleware creates HTTP middleware for JWT authentication.
// Validates tokens according to the provided options and injects user context.
// Handles token validation errors and expired tokens according to configuration.
// Returns a handler that can be chained with other middleware.
func AuthMiddleware(options AuthMiddlewareOptions) func(http.Handler) http.Handler {
	findToken := func(r *http.Request) string {
		return FindAuthToken(r, options.Config.GetPrivateKey(),
			options.Config.GetAuthCookieName(), options.Config.GetAuthTokenName())
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
			if err != nil && !(errors.Is(err, gjwt.ErrTokenExpired) && options.ExpiredAllowed) {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			// Build context with all claims
			ctx := r.Context()
			if baseClaims != nil {
				userID, _ := strconv.ParseUint(baseClaims.Subject, 10, 64)
				ctx = context.WithValue(ctx, mcontext.UserIDKey, uint(userID))
				ctx = context.WithValue(ctx, mcontext.AuthTokenKey, authToken)
			}
			if customClaims != nil {
				for key, value := range customClaims {
					ctx = context.WithValue(ctx, key, value)
				}
			}
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

func FindAuthToken(r *http.Request, secretKey ed25519.PrivateKey, cookieName string, queryParam string) string {
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

func (v *jwtValidator) Validate(token string, purpose string) (*gjwt.RegisteredClaims, error) {
	claims, _, err := v.ValidateWithClaims(token, purpose)
	return claims, err
}

func (v *jwtValidator) ValidateWithClaims(token string, purpose string) (*gjwt.RegisteredClaims, map[interface{}]interface{}, error) {
	domain := v.config.GetDomain()
	purposeTyped := jwt.JWTPurpose(purpose)

	// Check for custom claims type
	claimType, hasHandler := customClaimTypes[purpose]
	var customClaims gjwt.Claims
	if hasHandler {
		customClaims = reflect.New(claimType).Interface().(gjwt.Claims)
	} else {
		customClaims = &gjwt.RegisteredClaims{}
	}

	// Parse token with potential custom claims
	tokenObj, err := gjwt.ParseWithClaims(token, customClaims, func(token *gjwt.Token) (interface{}, error) {
		return v.config.GetPrivateKey().Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))

	if err != nil {
		return nil, nil, err
	}

	if !tokenObj.Valid {
		return nil, nil, jwt.ErrJWTInvalid
	}

	// Verify standard claims
	var baseClaims *gjwt.RegisteredClaims
	if rc, ok := customClaims.(*gjwt.RegisteredClaims); ok {
		baseClaims = rc
	} else if embeder, ok := customClaims.(interface{ GetRegisteredClaims() *gjwt.RegisteredClaims }); ok {
		baseClaims = embeder.GetRegisteredClaims()
	} else {
		return nil, nil, jwt.ErrJWTUnexpectedClaimsType
	}

	// Validate audience/purpose
	aud, _ := baseClaims.GetAudience()
	if purposeTyped != jwt.JWTPurposeNone && !JWTPurposeEqual(aud, purposeTyped) {
		return nil, nil, jwt.ErrJWTInvalid
	}

	// Validate issuer
	if baseClaims.Issuer != domain {
		return nil, nil, jwt.ErrJWTUnexpectedIssuer
	}

	// Store all claims under a single context key
	claimsMap := make(map[interface{}]interface{})
	if hasHandler {
		claimsMap[reflect.TypeOf(customClaims)] = customClaims
	}

	return baseClaims, claimsMap, nil
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

// claimsContextKey is used to store all custom claims in context
type claimsContextKey struct{}

// GetClaims retrieves custom claims from context by type
func GetClaims[T any](ctx context.Context) (T, bool) {
	var zero T
	claimsMap, ok := ctx.Value(claimsContextKey{}).(map[interface{}]interface{})
	if !ok {
		return zero, false
	}

	// Find first matching type in claims map
	for _, claim := range claimsMap {
		if tClaim, ok := claim.(T); ok {
			return tClaim, true
		}
	}
	return zero, false
}

// CustomClaimsHandler defines an interface for handling custom JWT claims
type CustomClaimsHandler interface {
	NewClaims() gjwt.Claims
}

var customClaimTypes = make(map[string]reflect.Type)

// RegisterClaimsHandler registers a custom claims type for a specific JWT purpose
func RegisterClaimsHandler(purpose string, claimType gjwt.Claims) {
	customClaimTypes[purpose] = reflect.TypeOf(claimType)
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
