package jwt

import (
	"crypto/ed25519"
	gjwt "github.com/golang-jwt/jwt/v5"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeToken(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)

	t.Run("valid token with custom claims", func(t *testing.T) {
		claims := &TestClaims{
			RegisteredClaims: &gjwt.RegisteredClaims{
				Subject: "123",
			},
			CustomField: "test",
			OtherField:  42,
		}

		token, err := CreateToken(privKey, "example.com", "123", PurposeLogin, time.Hour, WithClaims(claims))
		require.NoError(t, err)

		decoded, err := DecodeToken(token, &TestClaims{})
		require.NoError(t, err)

		decodedClaims, ok := decoded.(*TestClaims)
		require.True(t, ok)
		assert.Equal(t, "123", decodedClaims.Subject)
		assert.Equal(t, "test", decodedClaims.CustomField)
		assert.Equal(t, 42, decodedClaims.OtherField)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := DecodeToken("invalid.token", &gjwt.RegisteredClaims{})
		assert.Error(t, err)
	})

	t.Run("custom claims with custom claims type", func(t *testing.T) {
		// Create token with custom claims
		claims := &TestClaims{
			RegisteredClaims: &gjwt.RegisteredClaims{
				Subject: "123",
			},
			CustomField: "test",
		}
		token, err := CreateToken(privKey, "example.com", "123", PurposeLogin, time.Hour, WithClaims(claims))
		require.NoError(t, err)

		// Decode with matching custom claims type - should succeed
		decoded, err := DecodeToken(token, &TestClaims{})
		require.NoError(t, err)

		decodedClaims, ok := decoded.(*TestClaims)
		require.True(t, ok)
		assert.Equal(t, "test", decodedClaims.CustomField)
	})

	// Test case for when unexpected custom claims are present
	t.Run("unexpected custom claims", func(t *testing.T) {
		// Create token with custom claims
		type ExtraClaims struct {
			*gjwt.RegisteredClaims
			ExtraField string `json:"extra_field"`
		}
		token, err := CreateToken(privKey, "example.com", "123", PurposeLogin, time.Hour,
			WithClaims(&ExtraClaims{ExtraField: "value"}))
		require.NoError(t, err)

		// Try to decode with claims type that doesn't expect those fields
		type StrictClaims struct {
			*gjwt.RegisteredClaims
			// No extra fields
		}

		_, err = DecodeToken(token, &StrictClaims{})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrJWTUnexpectedClaimsType)
	})
}

func TestVerifyClaims(t *testing.T) {
	claims := &gjwt.RegisteredClaims{
		Issuer:   "example.com",
		Audience: []string{"login"},
	}

	t.Run("valid claims", func(t *testing.T) {
		err := VerifyClaims(claims, "example.com", PurposeLogin)
		assert.NoError(t, err)
	})

	t.Run("invalid issuer", func(t *testing.T) {
		err := VerifyClaims(claims, "wrong.com", PurposeLogin)
		assert.ErrorIs(t, err, ErrJWTUnexpectedIssuer)
	})

	t.Run("invalid purpose", func(t *testing.T) {
		err := VerifyClaims(claims, "example.com", Purpose2FA)
		assert.ErrorIs(t, err, ErrJWTInvalid)
	})
}

func TestDecodeAndVerify(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)

	t.Run("valid token", func(t *testing.T) {
		token, err := CreateToken(privKey, "example.com", "123", PurposeLogin, time.Hour)
		require.NoError(t, err)

		claims, err := DecodeAndVerify(token, &gjwt.RegisteredClaims{}, "example.com", PurposeLogin)
		require.NoError(t, err)
		assert.Equal(t, "123", claims.(*gjwt.RegisteredClaims).Subject)
	})

	t.Run("invalid issuer", func(t *testing.T) {
		token, err := CreateToken(privKey, "example.com", "123", PurposeLogin, time.Hour)
		require.NoError(t, err)

		_, err = DecodeAndVerify(token, &gjwt.RegisteredClaims{}, "wrong.com", PurposeLogin)
		assert.ErrorIs(t, err, ErrJWTUnexpectedIssuer)
	})
}
