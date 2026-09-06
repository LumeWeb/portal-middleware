package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	"go.lumeweb.com/portal-middleware/auth/validation"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// runRequestWithKeyLoggers drives the auth middleware with the given options
// and a bearer token, returning the recorder and any middleware error.
func runRequestWithKeyLoggers(t *testing.T, mockValidator *validation.MockTokenValidator, token string, extraOptions ...AuthMiddlewareOption) (*httptest.ResponseRecorder, error) {
	mockConfig, _ := setupAuthTest(t)

	options := append([]AuthMiddlewareOption{
		WithConfig(mockConfig),
		WithValidator(mockValidator),
		WithPurpose(jwt.PurposeLogin),
	}, extraOptions...)

	mw := AuthMiddleware(*NewAuthOptions(mockConfig, options...))

	req := httptest.NewRequest("GET", "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, rr)

	err := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})(c)
	return rr, err
}

func TestAuthMiddlewareKeyLogger(t *testing.T) {
	t.Run("loggers invoked on successful validation", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", "valid.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, (*gjwt.RegisteredClaims)(nil), nil).Once()

		logger := auth.NewMockJWTKeyLogger(t)
		logger.On("RecordAccess", mock.Anything, "valid.token", jwt.PurposeLogin, baseClaims, error(nil)).Once()

		_, err := runRequestWithKeyLoggers(t, mockValidator, "valid.token", WithKeyLogger(logger))
		require.NoError(t, err)
	})

	t.Run("loggers invoked on validation failure", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		mockValidator.On("ValidateWithClaims", "invalid.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(nil, nil, jwt.ErrJWTInvalid).Once()

		logger := auth.NewMockJWTKeyLogger(t)
		logger.On("RecordAccess", mock.Anything, "invalid.token", jwt.PurposeLogin, gjwt.Claims(nil), jwt.ErrJWTInvalid).Once()

		_, err := runRequestWithKeyLoggers(t, mockValidator, "invalid.token", WithKeyLogger(logger))
		require.Error(t, err)
	})

	t.Run("expired token still logged when allowed", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", "expired.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, (*gjwt.RegisteredClaims)(nil), gjwt.ErrTokenExpired).Once()

		logger := auth.NewMockJWTKeyLogger(t)
		logger.On("RecordAccess", mock.Anything, "expired.token", jwt.PurposeLogin, baseClaims, error(nil)).Once()

		_, err := runRequestWithKeyLoggers(t, mockValidator, "expired.token", WithKeyLogger(logger), WithExpiredAllowed(true))
		require.NoError(t, err)
	})

	t.Run("no loggers invoked for empty token", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		logger := auth.NewMockJWTKeyLogger(t)

		_, err := runRequestWithKeyLoggers(t, mockValidator, "", WithKeyLogger(logger), WithEmptyAllowed(true))
		require.NoError(t, err)
	})

	t.Run("panicking logger does not fail the request", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", "valid.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, (*gjwt.RegisteredClaims)(nil), nil).Once()

		logger := auth.NewMockJWTKeyLogger(t)
		logger.On("RecordAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { panic("plugin logger exploded") })

		_, err := runRequestWithKeyLoggers(t, mockValidator, "valid.token", WithKeyLogger(logger))
		require.NoError(t, err)
	})

	t.Run("all registered loggers are invoked in order", func(t *testing.T) {
		_, mockValidator := setupAuthTest(t)

		baseClaims := &gjwt.RegisteredClaims{Subject: "123"}
		mockValidator.On("ValidateWithClaims", "valid.token", jwt.PurposeLogin, &gjwt.RegisteredClaims{}).
			Return(baseClaims, (*gjwt.RegisteredClaims)(nil), nil).Once()

		var order []int
		loggerOne := auth.NewMockJWTKeyLogger(t)
		loggerOne.On("RecordAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, 1) }).Once()
		loggerTwo := auth.NewMockJWTKeyLogger(t)
		loggerTwo.On("RecordAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, 2) }).Once()

		_, err := runRequestWithKeyLoggers(t, mockValidator, "valid.token", WithKeyLogger(loggerOne, loggerTwo))
		require.NoError(t, err)
		require.Equal(t, []int{1, 2}, order)
	})
}
