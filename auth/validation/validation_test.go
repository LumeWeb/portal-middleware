package validation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
)

type CustomClaims struct {
	*gjwt.RegisteredClaims
	Role string `json:"role"`
}

func (c *CustomClaims) GetRegisteredClaims() *gjwt.RegisteredClaims {
	if c.RegisteredClaims == nil {
		c.RegisteredClaims = &gjwt.RegisteredClaims{}
	}
	return c.RegisteredClaims
}

func (c *CustomClaims) GetExpirationTime() (*gjwt.NumericDate, error) {
	return c.GetRegisteredClaims().GetExpirationTime()
}

func (c *CustomClaims) GetIssuedAt() (*gjwt.NumericDate, error) {
	return c.GetRegisteredClaims().GetIssuedAt()
}

func (c *CustomClaims) GetNotBefore() (*gjwt.NumericDate, error) {
	return c.GetRegisteredClaims().GetNotBefore()
}

func (c *CustomClaims) GetIssuer() (string, error) {
	return c.GetRegisteredClaims().GetIssuer()
}

func (c *CustomClaims) GetSubject() (string, error) {
	return c.GetRegisteredClaims().GetSubject()
}

func (c *CustomClaims) GetAudience() (gjwt.ClaimStrings, error) {
	return c.GetRegisteredClaims().GetAudience()
}

// ClaimSetter implementation
func (c *CustomClaims) SetIssuer(issuer string) {
	c.GetRegisteredClaims().Issuer = issuer
}

func (c *CustomClaims) SetSubject(subject string) {
	c.GetRegisteredClaims().Subject = subject
}

func (c *CustomClaims) SetExpiresAt(expiresAt *gjwt.NumericDate) {
	c.GetRegisteredClaims().ExpiresAt = expiresAt
}

func (c *CustomClaims) SetAudience(audience []string) {
	c.GetRegisteredClaims().Audience = audience
}

func TestValidatorWithDefaultRegisteredClaims(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	purpose := jwt.PurposeLogin
	expiration := time.Hour

	mockConfig := adapter.NewMockConfigProvider(t)
	mockConfig.On("GetPrivateKey").Return(priv).Maybe()
	mockConfig.On("GetDomain").Return(domain).Maybe()
	mockConfig.On("GetAuthCookieName").Return("auth").Maybe()
	mockConfig.On("GetAuthTokenName").Return("auth").Maybe()

	t.Run("valid token with only standard claims", func(t *testing.T) {
		validator := NewValidator(mockConfig) // No WithClaims option

		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
		)
		require.NoError(t, err)

		// Should work with nil claimsType
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, nil)
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)
		assert.Equal(t, domain, baseClaims.Issuer)
		assert.NotNil(t, customClaims) // Should return parsed claims
	})

	t.Run("valid token with standard claims when explicitly passing RegisteredClaims", func(t *testing.T) {
		validator := NewValidator(mockConfig) // No WithClaims option

		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
		)
		require.NoError(t, err)

		// Explicitly pass RegisteredClaims type
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, &gjwt.RegisteredClaims{})
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)
		assert.Equal(t, domain, baseClaims.Issuer)
		assert.NotNil(t, customClaims) // Should return the parsed claims
		assert.Equal(t, subject, customClaims.(*gjwt.RegisteredClaims).Subject)
	})

	t.Run("token with custom claims when only standard claims expected", func(t *testing.T) {
		validator := NewValidator(mockConfig) // No WithClaims option

		// Create token with custom claims
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&CustomClaims{}),
			jwt.WithModifiers(func(claims gjwt.Claims) {
				if cc, ok := claims.(*CustomClaims); ok {
					cc.Role = "admin"
				}
			}),
		)
		require.NoError(t, err)

		// Should still work but return the parsed claims
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, nil)
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)
		assert.Equal(t, domain, baseClaims.Issuer)
		assert.NotNil(t, customClaims) // Should return parsed claims
	})
}

func TestValidatorWithCustomClaims(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	domain := "test.com"
	subject := "user123"
	purpose := jwt.PurposeLogin
	expiration := time.Hour

	// Setup mock config
	mockConfig := adapter.NewMockConfigProvider(t)
	mockConfig.On("GetPrivateKey").Return(priv).Maybe()
	mockConfig.On("GetDomain").Return(domain).Maybe()
	mockConfig.On("GetAuthCookieName").Return("auth").Maybe()
	mockConfig.On("GetAuthTokenName").Return("auth").Maybe()

	t.Run("valid custom claims with ClaimSetter", func(t *testing.T) {
		validator := NewValidator(mockConfig)

		// Create token with custom claims using ClaimSetter
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&CustomClaims{}),
			jwt.WithModifiers(func(claims gjwt.Claims) {
				if cc, ok := claims.(*CustomClaims); ok {
					cc.Role = "admin"
				}
			}),
		)
		require.NoError(t, err)

		// Validate with claims
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, &CustomClaims{})
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)
		assert.Equal(t, domain, baseClaims.Issuer)

		// Verify custom claims
		cc, ok := customClaims.(*CustomClaims)
		require.True(t, ok)
		assert.Equal(t, "admin", cc.Role)
	})

	t.Run("valid custom claims with modifiers", func(t *testing.T) {
		validator := NewValidator(mockConfig, jwt.WithClaims(&CustomClaims{}))

		// Create token with custom claims using modifiers
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&CustomClaims{}),
			jwt.WithModifiers(func(claims gjwt.Claims) {
				if cc, ok := claims.(*CustomClaims); ok {
					cc.Role = "modifier_set"
					cc.SetIssuer(domain)
					cc.SetSubject(subject)
					cc.SetExpiresAt(gjwt.NewNumericDate(time.Now().Add(expiration)))
					cc.SetAudience([]string{string(purpose)})
				}
			}),
		)
		require.NoError(t, err)

		// Validate with claims
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, &CustomClaims{})
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)
		assert.Equal(t, domain, baseClaims.Issuer)

		// Verify custom claims
		cc, ok := customClaims.(*CustomClaims)
		require.True(t, ok)
		assert.Equal(t, "modifier_set", cc.Role)
	})

	t.Run("invalid custom claims type", func(t *testing.T) {
		validator := NewValidator(mockConfig, jwt.WithClaims(&CustomClaims{}))

		// Create token with different claims type
		type WrongClaims struct {
			*gjwt.RegisteredClaims
			Field string `json:"field"`
		}

		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&WrongClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{},
				Field:            "value",
			}),
			/*			jwt.WithModifiers(jwt.ClaimModifier(func(claims gjwt.Claims) {
						if claim, ok := claims.(*WrongClaims); ok {
							claim.Audience = gjwt.ClaimStrings{string(jwt.PurposeLogin)}
							claim.Issuer = domain
						}
					})),*/
		)
		require.NoError(t, err)

		// Should fail validation due to claims type mismatch
		_, _, err = validator.ValidateWithClaims(token, purpose, &CustomClaims{})
		assert.ErrorIs(t, err, jwt.ErrJWTUnexpectedClaimsType)
	})

	t.Run("custom claims with embedded registered claims", func(t *testing.T) {
		validator := NewValidator(mockConfig, jwt.WithClaims(&CustomClaims{}))

		// Create token with custom claims that embed RegisteredClaims
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&CustomClaims{
				RegisteredClaims: &gjwt.RegisteredClaims{
					ExpiresAt: gjwt.NewNumericDate(time.Now().Add(expiration)),
				},
				Role: "user",
			}),
		)
		require.NoError(t, err)

		// Validate with claims
		baseClaims, customClaims, err := validator.ValidateWithClaims(token, purpose, &CustomClaims{})
		require.NoError(t, err)
		assert.Equal(t, subject, baseClaims.Subject)

		// Verify custom claims
		cc, ok := customClaims.(*CustomClaims)
		require.True(t, ok)
		assert.Equal(t, "user", cc.Role)
	})

	t.Run("missing custom claims when expected", func(t *testing.T) {
		validator := NewValidator(mockConfig, jwt.WithClaims(&CustomClaims{}))

		// Create token without custom claims
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
		)
		require.NoError(t, err)

		// Should fail validation since token doesn't have expected custom claims
		_, _, err = validator.ValidateWithClaims(token, purpose, &CustomClaims{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected claims type")
	})

	t.Run("custom claims without registered claims", func(t *testing.T) {
		type ClaimsWithoutRegistered struct {
			gjwt.RegisteredClaims
			Role string `json:"role"`
		}

		validator := NewValidator(mockConfig, jwt.WithClaims(&ClaimsWithoutRegistered{}))

		// Create token with custom claims that embed RegisteredClaims
		token, err := jwt.CreateToken(
			priv,
			domain,
			subject,
			purpose,
			expiration,
			jwt.WithClaims(&ClaimsWithoutRegistered{
				RegisteredClaims: gjwt.RegisteredClaims{
					ExpiresAt: gjwt.NewNumericDate(time.Now().Add(expiration)),
				},
				Role: "test",
			}),
		)
		require.NoError(t, err)

		// Should pass validation by mapping to the claims type
		_, customClaims, err := validator.ValidateWithClaims(token, purpose, &ClaimsWithoutRegistered{})
		require.NoError(t, err)
		assert.Equal(t, "test", customClaims.(*ClaimsWithoutRegistered).Role)
	})
}
