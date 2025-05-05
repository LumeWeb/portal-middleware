package middleware

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
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
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).Return(true, struct{ ID uint }{ID: 1}, nil)
				mockAccessSvc.On("CheckAccess", uint(1), "example.com", "/api", "GET").Return(true, nil)
			},
			userID:         1,
			expectedStatus: http.StatusOK,
		},
		{
			name: "user exists but access denied",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(2)}).Return(true, struct{ ID uint }{ID: 2}, nil)
				mockAccessSvc.On("CheckAccess", uint(2), "example.com", "/api", "GET").Return(false, nil)
			},
			userID:         2,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "access check error",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(3)}).Return(true, struct{ ID uint }{ID: 3}, nil)
				mockAccessSvc.On("CheckAccess", uint(3), "example.com", "/api", "GET").Return(false, errors.New("db error"))
			},
			userID:         3,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "user does not exist",
			setupMocks: func(mockUserSvc *coreMocks.MockUserService, mockAccessSvc *coreMocks.MockAccessService) {
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(4)}).Return(false, nil, nil)
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

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := middleware(testHandler)

			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			if tc.userID != 0 {
				req = req.WithContext(context.WithValue(req.Context(), mo.UserIDKey, tc.userID))
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			mockUserSvc.AssertExpectations(t)
			mockAccessSvc.AssertExpectations(t)
		})
	}
}
