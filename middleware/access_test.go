package middleware

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	authMiddleware "go.lumeweb.com/portal-middleware/auth/middleware" // Import the auth middleware package
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"

	"go.lumeweb.com/portal-middleware/auth" // Import the auth package for mocks
)

func testAccessMiddlewareHelper(t *testing.T, tests []struct {
	name                    string
	setupContext            func() core.Context
	customMiddlewareFactory func(core.Context) echo.MiddlewareFunc // Updated to echo.MiddlewareFunc
	userID                  uint
	path                    string
	expectedStatus          int
}, createMiddleware func(core.Context) echo.MiddlewareFunc) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coreCtx := tt.setupContext()
			var ms echo.MiddlewareFunc

			// Check if a custom middleware factory is provided in the test case
			if tt.customMiddlewareFactory != nil {
				ms = tt.customMiddlewareFactory(coreCtx)
			} else {
				ms = createMiddleware(coreCtx)
			}

			e := echo.New()
			e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					if tt.userID > 0 {
						c.Set(string(mo.UserIDKey), tt.userID)
					}
					return next(c)
				}
			})
			e.Use(ms)
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

func TestAccessMiddleware(t *testing.T) {
	tests := []struct {
		name                    string
		setupContext            func() core.Context
		customMiddlewareFactory func(core.Context) echo.MiddlewareFunc
		userID                  uint
		path                    string
		expectedStatus          int
	}{
		{
			name: "access granted",
			setupContext: func() core.Context {
				// We don't need to setup core services in the context for this test
				// because we will mock the adapter interfaces directly.
				return coreTesting.NewTestContext(t)
			},
			customMiddlewareFactory: func(coreCtx core.Context) echo.MiddlewareFunc {
				// Create mocks for the interfaces the middleware directly uses
				mockUserChecker := auth.NewMockUserChecker(t)     // Use auth.NewMockUserChecker
				mockAccessChecker := auth.NewMockAccessChecker(t) // Use auth.NewMockAccessChecker

				// Setup mock expectations for the adapter interfaces
				mockUserChecker.On("AccountExists", uint(1)).Return(true, nil).Once()
				mockAccessChecker.On("CheckAccess", uint(1), "example.com", "/allowed", "GET").
					Return(true, nil).Once()

				// Instantiate the middleware with the mocked interfaces
				return authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)
			},
			userID:         1,
			path:           "/allowed",
			expectedStatus: http.StatusOK,
		},
		{
			name: "access denied",
			setupContext: func() core.Context {
				return coreTesting.NewTestContext(t)
			},
			customMiddlewareFactory: func(coreCtx core.Context) echo.MiddlewareFunc {
				mockUserChecker := auth.NewMockUserChecker(t)
				mockAccessChecker := auth.NewMockAccessChecker(t)

				mockUserChecker.On("AccountExists", uint(1)).Return(true, nil).Once()
				mockAccessChecker.On("CheckAccess", uint(1), mock.Anything, "/denied", "GET").
					Return(false, nil).Once()

				return authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)
			},
			userID:         1,
			path:           "/denied",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "access error",
			setupContext: func() core.Context {
				return coreTesting.NewTestContext(t)
			},
			customMiddlewareFactory: func(coreCtx core.Context) echo.MiddlewareFunc {
				mockUserChecker := auth.NewMockUserChecker(t)
				mockAccessChecker := auth.NewMockAccessChecker(t)

				mockUserChecker.On("AccountExists", uint(1)).Return(true, nil).Once()
				mockAccessChecker.On("CheckAccess", uint(1), mock.Anything, "/error", "GET").
					Return(false, errors.New("permission check error")).Once()

				return authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)
			},
			userID:         1,
			path:           "/error",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "user does not exist",
			setupContext: func() core.Context {
				return coreTesting.NewTestContext(t)
			},
			customMiddlewareFactory: func(coreCtx core.Context) echo.MiddlewareFunc {
				mockUserChecker := auth.NewMockUserChecker(t)
				mockAccessChecker := auth.NewMockAccessChecker(t)

				mockUserChecker.On("AccountExists", uint(1001)).Return(false, nil).Once()
				// AccessChecker.CheckAccess should not be called if user doesn't exist
				mockAccessChecker.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

				return authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)
			},
			userID:         1001,
			path:           "/allowed",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "no user in context",
			setupContext: func() core.Context {
				return coreTesting.NewTestContext(t)
			},
			customMiddlewareFactory: func(coreCtx core.Context) echo.MiddlewareFunc {
				mockUserChecker := auth.NewMockUserChecker(t)
				mockAccessChecker := auth.NewMockAccessChecker(t)

				// Neither AccountExists nor CheckAccess should be called if no user in context
				mockUserChecker.On("AccountExists", mock.Anything).Return(false, nil).Maybe()
				mockAccessChecker.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

				return authMiddleware.AccessMiddleware(mockUserChecker, mockAccessChecker)
			},
			userID:         0,
			path:           "/allowed",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	// Use the helper with nil for the default middleware factory, as we are providing
	// custom factories in each test case.
	testAccessMiddlewareHelper(t, tests, nil)
}
