package middleware

import (
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAccessMiddlewareFromCore(t *testing.T) {
	testCases := []struct {
		name           string
		setupMocks     func(*coreMocks.MockUserService, *coreMocks.MockAccessService)
		userID         uint
		expectedStatus int
	}{
		{
			name: "no user in context",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				// No expectations as middleware should fail early
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "user exists and access granted",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("AccountExists", uint(1)).Return(true, &models.User{Model: gorm.Model{ID: 1}}, nil)
				mockAccessSvc.On("CheckAccess", uint(1), "example.com", "/api", "GET").Return(true, nil)
			},
			userID:         1,
			expectedStatus: http.StatusOK,
		},
		{
			name: "user exists but access denied",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("AccountExists", uint(2)).Return(true, &models.User{Model: gorm.Model{ID: 2}}, nil)
				mockAccessSvc.On("CheckAccess", uint(2), "example.com", "/api", "GET").Return(false, nil)
			},
			userID:         2,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "access check error",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("AccountExists", uint(3)).Return(true, &models.User{Model: gorm.Model{ID: 3}}, nil)
				mockAccessSvc.On("CheckAccess", uint(3), "example.com", "/api", "GET").Return(false, gorm.ErrRecordNotFound)
			},
			userID:         3,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "user does not exist",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("AccountExists", uint(4)).Return(false, nil, gorm.ErrRecordNotFound)
			},
			userID:         4,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := coreTesting.NewTestContext(t)
			mockUserSvc := coreMocks.NewMockUserService(t)
			mockAccessSvc := coreMocks.NewMockAccessService(t)

			tc.setupMocks(mockUserSvc, mockAccessSvc)

			ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
			ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)

			middleware := NewAccessMiddlewareFromCore(ctx)
			require.NotNil(t, middleware)

			e := echo.New()
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tc.userID != 0 {
				c.Set(string(mo.UserIDKey), tc.userID)
			}

			handler := middleware(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})

			err := handler(c)
			if tc.expectedStatus != http.StatusOK {
				require.Error(t, err)
				httpErr, ok := err.(*echo.HTTPError)
				require.True(t, ok)
				assert.Equal(t, tc.expectedStatus, httpErr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedStatus, rec.Code)
			}
			mockUserSvc.AssertExpectations(t)
			mockAccessSvc.AssertExpectations(t)
		})
	}
}
