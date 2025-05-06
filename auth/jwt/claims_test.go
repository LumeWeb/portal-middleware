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

func TestGetClaimsType(t *testing.T) {
	t.Run("no options returns RegisteredClaims", func(t *testing.T) {
		claimsType := GetClaimsType(nil)
		_, ok := claimsType.(*gjwt.RegisteredClaims)
		assert.True(t, ok, "should return RegisteredClaims by default")
	})

	t.Run("empty options returns RegisteredClaims", func(t *testing.T) {
		claimsType := GetClaimsType([]Option{})
		_, ok := claimsType.(*gjwt.RegisteredClaims)
		assert.True(t, ok, "should return RegisteredClaims by default")
	})

	t.Run("with claims option returns custom claims type", func(t *testing.T) {
		expectedClaims := &TestClaims{}
		opts := []Option{WithClaims(expectedClaims)}

		claimsType := GetClaimsType(opts)
		assert.Equal(t, expectedClaims, claimsType, "should return the custom claims type")
	})

	t.Run("multiple options returns first claims type", func(t *testing.T) {
		expectedClaims := &TestClaims{}
		opts := []Option{
			WithModifiers(func(c gjwt.Claims) {}),
			WithClaims(expectedClaims),
			WithClaims(&gjwt.RegisteredClaims{}),
		}

		claimsType := GetClaimsType(opts)
		assert.Equal(t, expectedClaims, claimsType, "should return first custom claims type")
	})

	t.Run("with default parameter returns default when no options", func(t *testing.T) {
		defaultClaims := &TestClaims{}
		claimsType := GetClaimsType(nil, defaultClaims)
		assert.Equal(t, defaultClaims, claimsType, "should return default when no options")
	})

	t.Run("with default parameter returns default when empty options", func(t *testing.T) {
		defaultClaims := &TestClaims{}
		claimsType := GetClaimsType([]Option{}, defaultClaims)
		assert.Equal(t, defaultClaims, claimsType, "should return default when empty options")
	})

	t.Run("with default parameter returns custom claims type from options", func(t *testing.T) {
		expectedClaims := &TestClaims{}
		defaultClaims := &gjwt.RegisteredClaims{}
		opts := []Option{WithClaims(expectedClaims)}

		claimsType := GetClaimsType(opts, defaultClaims)
		assert.Equal(t, expectedClaims, claimsType, "should return custom claims type from options")
	})

	t.Run("with default parameter skips RegisteredClaims in options", func(t *testing.T) {
		expectedClaims := &TestClaims{}
		defaultClaims := &gjwt.RegisteredClaims{}
		opts := []Option{
			WithClaims(&gjwt.RegisteredClaims{}),
			WithClaims(expectedClaims),
		}

		claimsType := GetClaimsType(opts, defaultClaims)
		assert.Equal(t, expectedClaims, claimsType, "should skip RegisteredClaims in options when default is provided")
	})

	t.Run("with default parameter returns default when options has only RegisteredClaims", func(t *testing.T) {
		expectedClaims := &TestClaims{}
		opts := []Option{WithClaims(&gjwt.RegisteredClaims{})}

		claimsType := GetClaimsType(opts, expectedClaims)
		assert.Equal(t, expectedClaims, claimsType, "should return default when options has only RegisteredClaims")
	})

	t.Run("with nil default falls back to RegisteredClaims", func(t *testing.T) {
		opts := []Option{WithClaims(&gjwt.RegisteredClaims{})}

		claimsType := GetClaimsType(opts, nil)
		_, ok := claimsType.(*gjwt.RegisteredClaims)
		assert.True(t, ok, "should fall back to RegisteredClaims when default is nil")
	})
}
