package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	gjwt "github.com/golang-jwt/jwt/v5"
	"reflect"
)

// DecodeToken decodes a JWT token without validation and returns the claims
func DecodeToken(tokenString string, claimsType gjwt.Claims) (gjwt.Claims, error) {
	if claimsType == nil {
		return nil, errors.New("claims type cannot be nil")
	}

	// Ensure we have a pointer to decode into
	claimsValue := reflect.ValueOf(claimsType)
	if claimsValue.Kind() != reflect.Ptr {
		// Create new pointer of same type
		ptrType := reflect.PtrTo(reflect.TypeOf(claimsType))
		newPtr := reflect.New(ptrType.Elem())
		claimsType = newPtr.Interface().(gjwt.Claims)
	}

	// Create a new parser without claims validation
	parser := gjwt.NewParser(gjwt.WithoutClaimsValidation())

	// Parse the token
	token, _, err := parser.ParseUnverified(tokenString, claimsType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTInvalid, err)
	}

	// Get raw claims data
	var rawClaims map[string]interface{}
	data, err := json.Marshal(token.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTInvalid, err)
	}
	if err := json.Unmarshal(data, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTInvalid, err)
	}

	// Create new instance of expected type
	decodedClaims := reflect.New(reflect.TypeOf(claimsType).Elem()).Interface().(gjwt.Claims)

	// Check if we're expecting custom claims (not just RegisteredClaims)
	_, isStandard := decodedClaims.(*gjwt.RegisteredClaims)
	if !isStandard {
		// If we expect custom claims but token only has standard claims, return error
		hasOnlyStandardClaims := true
		outer:
		for claim := range rawClaims {
			switch claim {
			case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
				continue // Skip standard claims
			default:
				hasOnlyStandardClaims = false
				break outer
			}
		}

		if hasOnlyStandardClaims {
			return nil, fmt.Errorf("%w: expected custom claims but only standard claims present", ErrJWTUnexpectedClaimsType)
		}

		if err := ValidateClaimsStructure(rawClaims, decodedClaims); err != nil {
			return nil, err
		}
	}

	if err := MapClaims(rawClaims, decodedClaims); err != nil {
		return nil, err
	}

	return decodedClaims, nil
}

// VerifyClaims verifies standard JWT claims against expected values
func VerifyClaims(claims gjwt.Claims, expectedIssuer string, expectedPurpose Purpose) error {
	// Get base claims
	var baseClaims *gjwt.RegisteredClaims
	switch c := claims.(type) {
	case *gjwt.RegisteredClaims:
		baseClaims = c
	default:
		if getter, ok := c.(interface{ GetRegisteredClaims() *gjwt.RegisteredClaims }); ok {
			baseClaims = getter.GetRegisteredClaims()
		} else {
			return fmt.Errorf("%w: claims does not implement GetRegisteredClaims()", ErrJWTInvalid)
		}
	}

	// Verify issuer
	if expectedIssuer != "" {
		issuer, err := baseClaims.GetIssuer()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJWTUnexpectedIssuer, err)
		}
		if issuer != expectedIssuer {
			return fmt.Errorf("%w: got %q want %q", ErrJWTUnexpectedIssuer, issuer, expectedIssuer)
		}
	}

	// Verify purpose/audience
	if expectedPurpose != PurposeNone {
		audience, err := baseClaims.GetAudience()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJWTInvalid, err)
		}
		if !PurposeEqual(audience, expectedPurpose) {
			return fmt.Errorf("%w: audience does not contain purpose %q", ErrJWTInvalid, expectedPurpose)
		}
	}

	return nil
}

// DecodeAndVerify decodes a token and verifies its standard claims
func DecodeAndVerify(tokenString string, claimsType gjwt.Claims, expectedIssuer string, expectedPurpose Purpose) (gjwt.Claims, error) {
	claims, err := DecodeToken(tokenString, claimsType)
	if err != nil {
		return nil, err
	}

	if err := VerifyClaims(claims, expectedIssuer, expectedPurpose); err != nil {
		return nil, err
	}

	return claims, nil
}
