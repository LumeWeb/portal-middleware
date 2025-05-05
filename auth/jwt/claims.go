package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	gjwt "github.com/golang-jwt/jwt/v5"
	"reflect"
	"strings"
)

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
