package jwt

import (
	"crypto/ed25519"
	"errors"
	gjwt "github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

// Purpose defines the intended use case for a JWT token within the system.
// This helps prevent token reuse across different application components.
type Purpose string

// VerifyTokenFunc is a callback type for performing custom claim validations.
// Used to add additional security checks beyond standard JWT validation.
type VerifyTokenFunc func(claim *gjwt.RegisteredClaims) error

// JWT validation error definitions. These provide specific error types
// for different validation failure scenarios.
var (
	// ErrJWTInvalid indicates general token invalidity (expired, malformed, etc)
	ErrJWTInvalid = gjwt.ErrTokenInvalidClaims

	// ErrJWTUnexpectedClaimsType occurs when claims structure doesn't match expectations
	ErrJWTUnexpectedClaimsType = errors.New("unexpected claims type")

	// ErrJWTUnexpectedIssuer indicates token was issued by unauthorized authority
	ErrJWTUnexpectedIssuer = errors.New("unexpected issuer")
)

// Standard JWT purpose constants that define allowed token usages
const (
	PurposeNone  Purpose = ""      // No specific purpose required
	PurposeLogin Purpose = "login" // Authentication tokens
	Purpose2FA   Purpose = "2fa"   // Two-factor authentication tokens
)

// ClaimModifier defines a function type for modifying JWT claims
type ClaimModifier func(claims gjwt.Claims)

// Option defines the interface for JWT configuration options
type Option interface {
	Apply(*jwtOptions)
}

type jwtOptions struct {
	claims    gjwt.Claims
	modifiers []ClaimModifier
}

// WithClaimsOpt implements Option to specify custom claims
type WithClaimsOpt struct{ claims gjwt.Claims }

func (wco *WithClaimsOpt) Claims() gjwt.Claims {
	return wco.claims
}

func (o WithClaimsOpt) Apply(opts *jwtOptions) {
	opts.claims = o.claims
}

func WithClaims(c gjwt.Claims) Option {
	return WithClaimsOpt{c}
}

// WithModifiersOpt implements Option to add claim modifiers
type WithModifiersOpt struct{ modifiers []ClaimModifier }

func (o WithModifiersOpt) Apply(opts *jwtOptions) {
	opts.modifiers = append(opts.modifiers, o.modifiers...)
}

func WithModifiers(m ...ClaimModifier) Option {
	return WithModifiersOpt{m}
}

// CreateToken creates a new JWT token with the specified parameters
func CreateToken(privateKey ed25519.PrivateKey, domain string, subject string, purpose Purpose, expiration time.Duration, opts ...Option) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is required")
	}

	// Process options
	options := &jwtOptions{}
	for _, opt := range opts {
		opt.Apply(options)
	}

	// If no claims provided, use default RegisteredClaims
	if options.claims == nil {
		options.claims = &gjwt.RegisteredClaims{}
	}

	// Set standard claims
	if registeredClaims, ok := options.claims.(*gjwt.RegisteredClaims); ok {
		registeredClaims.Issuer = domain
		registeredClaims.Subject = subject
		registeredClaims.ExpiresAt = gjwt.NewNumericDate(time.Now().Add(expiration))
		if purpose != PurposeNone {
			registeredClaims.Audience = []string{string(purpose)}
		}
	} else if claims, ok := options.claims.(gjwt.Claims); ok {
		// Handle custom claims that embed RegisteredClaims
		if customClaims, ok := claims.(interface {
			SetIssuer(string)
			SetSubject(string)
			SetExpiresAt(*gjwt.NumericDate)
			SetAudience([]string)
		}); ok {
			customClaims.SetIssuer(domain)
			customClaims.SetSubject(subject)
			customClaims.SetExpiresAt(gjwt.NewNumericDate(time.Now().Add(expiration)))
			if purpose != PurposeNone {
				customClaims.SetAudience([]string{string(purpose)})
			}
		}
	}

	// Apply modifiers
	for _, modifier := range options.modifiers {
		modifier(options.claims)
	}

	// Create and sign the token
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, options.claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Send creates and sets a JWT token in the HTTP response
func Send(w http.ResponseWriter, privateKey ed25519.PrivateKey, domain string, cookieName string, subject string, purpose Purpose, expiration time.Duration, opts ...Option) (string, error) {
	// Use the exported CreateToken instead of the internal one
	token, err := CreateToken(privateKey, domain, subject, purpose, expiration, opts...)
	if err != nil {
		return "", err
	}

	// Set cookie with the token
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Domain:   domain,
		Path:     "/",
		Expires:  time.Now().Add(expiration),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	return token, nil
}

// RefreshToken creates a new token using an existing token's claims
func RefreshToken(tokenString string, privateKey ed25519.PrivateKey, domain string, expiration time.Duration) (string, error) {
	// Create a parser without claims validation
	parser := gjwt.NewParser(gjwt.WithoutClaimsValidation())

	// Parse without validation first
	token, _, err := parser.ParseUnverified(tokenString, &gjwt.RegisteredClaims{})
	if err != nil {
		return "", err
	}

	// Get claims from original token
	claims, ok := token.Claims.(*gjwt.RegisteredClaims)
	if !ok {
		return "", errors.New("invalid claims type")
	}

	// Create new claims with updated expiration
	newClaims := &gjwt.RegisteredClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		NotBefore: gjwt.NewNumericDate(time.Now()),
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(expiration)),
	}

	// Create new token with refreshed expiration
	newToken := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, newClaims)
	signedToken, err := newToken.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func Options(opts ...Option) []Option {
	return opts
}

func PurposeEqual(aud gjwt.ClaimStrings, purpose Purpose) bool {
	for _, a := range aud {
		if a == string(purpose) {
			return true
		}
	}
	return false
}
