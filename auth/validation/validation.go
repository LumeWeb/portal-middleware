package validation

import (
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
)

func NewValidator(config adapter.ConfigProvider, opts ...jwt.Option) TokenValidator {
	return &jwtValidator{config: config, options: opts}
}

type jwtValidator struct {
	config  adapter.ConfigProvider
	options []jwt.Option
}

// Type assertions to ensure interfaces are implemented correctly
var (
	_ TokenValidator = (*jwtValidator)(nil)
)

// TokenValidator defines an interface for validating JWT tokens
// TokenValidator handles JWT token validation and claims extraction.
// Implementations should verify token signatures and audience/purpose claims.
type TokenValidator interface {
	Validate(token string, purpose jwt.Purpose) (*gjwt.RegisteredClaims, error)
	ValidateWithClaims(token string, purpose jwt.Purpose) (*gjwt.RegisteredClaims, gjwt.Claims, error)
}

func (v *jwtValidator) Validate(token string, purpose jwt.Purpose) (*gjwt.RegisteredClaims, error) {
	claims, _, err := v.ValidateWithClaims(token, purpose)
	return claims, err
}

func (v *jwtValidator) ValidateWithClaims(token string, purpose jwt.Purpose) (*gjwt.RegisteredClaims, gjwt.Claims, error) {
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
	if purpose != jwt.PurposeNone && !jwt.PurposeEqual(aud, purpose) {
		return nil, nil, jwt.ErrJWTInvalid
	}

	// Validate issuer
	if baseClaims.Issuer != domain {
		return nil, nil, jwt.ErrJWTUnexpectedIssuer
	}

	return baseClaims, tokenObj.Claims, nil
}
