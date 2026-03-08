package middleware_test

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-middleware/auth"
	mo "go.lumeweb.com/portal-middleware/context"
	authMiddleware "go.lumeweb.com/portal-middleware/auth/middleware"
)

func TestAccountVerifiedMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		userID         uint
		path           string
		expectedStatus int
	}{
		{
			name:           "valid verified user",
			userID:         1,
			path:           "/test",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user not verified",
			userID:         2,
			path:           "/test",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "error checking verification",
			userID:         3,
			path:           "/test",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "no user in context",
			userID:         0,
			path:           "/test",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use auth package mocks
			mockUserChecker := auth.NewMockUserChecker(t)

			// Configure mock expectations based on test case
			if tt.userID > 0 {
				if tt.expectedStatus == http.StatusOK {
					mockUserChecker.On("IsAccountVerified", mock.Anything, tt.userID).Return(true, nil).Once()
				} else if tt.expectedStatus == http.StatusForbidden {
					mockUserChecker.On("IsAccountVerified", mock.Anything, tt.userID).Return(false, nil).Once()
				} else if tt.expectedStatus == http.StatusInternalServerError {
					mockUserChecker.On("IsAccountVerified", mock.Anything, tt.userID).
						Return(false, errors.New("database error checking verification")).Once()
				} else {
					mockUserChecker.On("IsAccountVerified", mock.Anything, tt.userID).Return(false, nil).Maybe()
				}
			}

			mw := authMiddleware.AccountVerified(mockUserChecker)

			e := echo.New()
			e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					if tt.userID > 0 {
						c.Set(string(mo.UserIDKey), tt.userID)
					}
					return next(c)
				}
			})
			e.Use(mw)
			e.GET(tt.path, func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Expected status code %d, got %d", tt.expectedStatus, rec.Code)
		})
	}
}
