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

func TestAccessMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		userID         uint
		path           string
		expectedStatus int
	}{
		{
			name:           "access granted",
			userID:         1,
			path:           "/allowed",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "access denied",
			userID:         2,
			path:           "/denied",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "no user in context",
			userID:         0,
			path:           "/allowed",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use auth package mocks instead of core mocks
			mockUserChecker := auth.NewMockUserChecker(t)
			mockAccessChecker := auth.NewMockAccessChecker(t)

			// Configure mock expectations based on test case
			if tt.userID > 0 {
				mockUserChecker.On("AccountExists", mock.Anything, tt.userID).Return(true, nil).Maybe()
				if tt.expectedStatus == http.StatusOK {
					mockAccessChecker.On("CheckAccess", mock.Anything, tt.userID, mock.Anything, tt.path, "GET").Return(true, nil).Once()
				} else if tt.expectedStatus == http.StatusUnauthorized {
					mockAccessChecker.On("CheckAccess", mock.Anything, tt.userID, mock.Anything, tt.path, "GET").Return(false, nil).Once()
				} else {
					mockAccessChecker.On("CheckAccess", mock.Anything, tt.userID, mock.Anything, tt.path, "GET").Return(false, errors.New("error")).Once()
				}
			}

			mw := authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)

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
			req.Host = "example.com"
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Expected status code %d, got %d", tt.expectedStatus, rec.Code)
		})
	}
}
