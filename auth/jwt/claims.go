package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	gjwt "github.com/golang-jwt/jwt/v5"
	"reflect"
	"strings"
)

type RegisteredClaims = gjwt.RegisteredClaims

// ValidateClaimsStructure validates that raw JWT claims match the expected struct
func ValidateClaimsStructure(rawClaims gjwt.MapClaims, expected interface{}) error {
	if expected == nil {
		return errors.New("claims type cannot be nil")
	}

	expectedType := reflect.TypeOf(expected)
	if expectedType.Kind() == reflect.Ptr {
		expectedType = expectedType.Elem()
	}

	// Get JSON tags from expected struct
	expectedFields := make(map[string]bool)
	for i := 0; i < expectedType.NumField(); i++ {
		field := expectedType.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			if commaIdx := strings.Index(jsonTag, ","); commaIdx != -1 {
				jsonTag = jsonTag[:commaIdx]
			}
			expectedFields[jsonTag] = true
		}
	}

	// Check all non-standard claims in JWT exist in expected struct
	for claim := range rawClaims {
		switch claim {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
			continue // Skip standard claims
		default:
			if !expectedFields[claim] {
				return fmt.Errorf("%w: unexpected claim field '%s'", ErrJWTUnexpectedClaimsType, claim)
			}
		}
	}

	return nil
}

// MapClaims maps raw JWT claims to a target struct
func MapClaims(rawClaims gjwt.MapClaims, target interface{}) error {
	data, err := json.Marshal(rawClaims)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWTInvalid, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w: %v", ErrJWTUnexpectedClaimsType, err)
	}

	return nil
}

// GetClaimsTypeFromOptions extracts the claims type from JWT options with optional default
func GetClaimsType(opts []Option, defaultClaims ...gjwt.Claims) gjwt.Claims {
	var fallback gjwt.Claims
	if len(defaultClaims) > 0 {
		fallback = defaultClaims[0]
	} else {
		fallback = &gjwt.RegisteredClaims{}
	}

	for _, opt := range opts {
		if claimOpt, ok := opt.(WithClaimsOpt); ok {
			// If we have a fallback, skip RegisteredClaims in options
			if fallback != nil {
				if _, isRegistered := claimOpt.Claims().(*gjwt.RegisteredClaims); !isRegistered {
					return claimOpt.Claims()
				}
				continue
			}
			return claimOpt.Claims()
		}
	}

	return fallback
}
