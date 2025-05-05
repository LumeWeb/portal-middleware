package jwt

import (
	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type TestClaims struct {
	*gjwt.RegisteredClaims
	CustomField string `json:"custom_field"`
	OtherField  int    `json:"other_field"`
}

func (t *TestClaims) GetRegisteredClaims() *gjwt.RegisteredClaims {
	return t.RegisteredClaims
}

func TestValidateClaimsStructure(t *testing.T) {
	t.Run("valid custom claims", func(t *testing.T) {
		rawClaims := gjwt.MapClaims{
			"iss":          "example.com",
			"sub":          "123",
			"custom_field": "test",
			"other_field":  42,
		}

		err := ValidateClaimsStructure(rawClaims, &TestClaims{})
		assert.NoError(t, err)
	})

	t.Run("invalid claims structure", func(t *testing.T) {
		rawClaims := gjwt.MapClaims{
			"iss":           "example.com",
			"sub":           "123",
			"invalid_field": "bad", // Not in TestClaims
		}

		err := ValidateClaimsStructure(rawClaims, &TestClaims{})
		assert.ErrorIs(t, err, ErrJWTUnexpectedClaimsType)
	})
}

func TestMapClaims(t *testing.T) {
	t.Run("successful claims mapping", func(t *testing.T) {
		rawClaims := gjwt.MapClaims{
			"iss":          "example.com",
			"sub":          "123",
			"custom_field": "test",
			"other_field":  42,
		}

		var claims TestClaims
		err := MapClaims(rawClaims, &claims)
		require.NoError(t, err)
		assert.Equal(t, "test", claims.CustomField)
		assert.Equal(t, 42, claims.OtherField)
	})
}
