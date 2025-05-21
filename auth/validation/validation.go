package validation

import (
	"encoding/json"
	gjwt "github.com/golang-jwt/jwt/v5"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"reflect"
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
	ValidateWithClaims(token string, purpose jwt.Purpose, claimsType gjwt.Claims) (*gjwt.RegisteredClaims, gjwt.Claims, error)
}

func (v *jwtValidator) Validate(token string, purpose jwt.Purpose) (*gjwt.RegisteredClaims, error) {
	claims, _, err := v.ValidateWithClaims(token, purpose, &gjwt.RegisteredClaims{})
	return claims, err
}

func (v *jwtValidator) ValidateWithClaims(token string, purpose jwt.Purpose, claimsType gjwt.Claims) (*gjwt.RegisteredClaims, gjwt.Claims, error) {
	domain := v.config.GetDomain()

	// 1. First parse without validation to get raw claims
	parser := gjwt.NewParser(gjwt.WithoutClaimsValidation())
	tokenObj, _, err := parser.ParseUnverified(token, gjwt.MapClaims{})
	if err != nil {
		return nil, nil, err
	}

	rawClaims, ok := tokenObj.Claims.(gjwt.MapClaims)
	if !ok {
		return nil, nil, jwt.ErrJWTInvalid
	}

	// Handle nil claimsType by defaulting to RegisteredClaims
	if claimsType == nil {
		claimsType = &gjwt.RegisteredClaims{}
	}

	// Create new instance of the expected claims type
	customClaims := reflect.New(reflect.TypeOf(claimsType).Elem()).Interface().(gjwt.Claims)

	// Only validate custom claims structure if we expect custom claims
	if _, isStandard := claimsType.(*gjwt.RegisteredClaims); !isStandard {
		// Check if token actually contains any custom claims
		hasCustomClaims := false
		for claim := range rawClaims {
			switch claim {
			case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
				continue // Skip standard claims
			default:
				hasCustomClaims = true
				break
			}
		}

		if !hasCustomClaims {
			return nil, nil, jwt.ErrJWTUnexpectedClaimsType
		}

		if err := jwt.ValidateClaimsStructure(rawClaims, customClaims); err != nil {
			return nil, nil, err
		}
	}

	// Map all claims (both standard and custom)
	if err := jwt.MapClaims(rawClaims, customClaims); err != nil {
		return nil, nil, err
	}

	// 4. Now parse with full validation
	var claimsToParse gjwt.Claims
	if customClaims != nil {
		claimsToParse = customClaims
	} else {
		claimsToParse = &gjwt.RegisteredClaims{}
	}

	tokenObj, err = gjwt.ParseWithClaims(token, claimsToParse, func(token *gjwt.Token) (interface{}, error) {
		return v.config.GetPrivateKey().Public(), nil
	}, gjwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		return nil, nil, err
	}

	// 5. Extract base claims
	var baseClaims *gjwt.RegisteredClaims
	switch c := tokenObj.Claims.(type) {
	case *gjwt.RegisteredClaims:
		baseClaims = c
	default:
		// Handle both embedded and non-embedded RegisteredClaims
		if getter, ok := c.(interface{ GetRegisteredClaims() *gjwt.RegisteredClaims }); ok {
			baseClaims = getter.GetRegisteredClaims()
		} else {
			// For custom claims without RegisteredClaims, try to map standard claims
			baseClaims = &gjwt.RegisteredClaims{}
			if err := mapStandardClaims(rawClaims, baseClaims); err == nil {
				// If we successfully mapped standard claims, use them
				return baseClaims, c, nil
			}
			// Otherwise return empty base claims
			return &gjwt.RegisteredClaims{}, c, nil
		}
	}

	// 6. Validate audience/purpose
	if purpose != jwt.PurposeNone {
		aud, err := baseClaims.GetAudience()
		if err != nil {
			return nil, nil, jwt.ErrJWTInvalid
		}

		// Only validate audience if we have standard claims or custom claims with audience
		if _, isStandard := claimsType.(*gjwt.RegisteredClaims); !isStandard || len(aud) > 0 {
			if !jwt.PurposeEqual(aud, purpose) {
				return nil, nil, jwt.ErrJWTInvalid
			}
		}
	}

	// 7. Validate issuer
	if baseClaims.Issuer != "" {
		iss, err := baseClaims.GetIssuer()
		if err != nil || iss != domain {
			return nil, nil, jwt.ErrJWTUnexpectedIssuer
		}
	}
	return baseClaims, tokenObj.Claims, nil
}
func mapStandardClaims(rawClaims gjwt.MapClaims, target *gjwt.RegisteredClaims) error {
	data, err := json.Marshal(rawClaims)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
