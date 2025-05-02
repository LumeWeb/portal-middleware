package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func testAccountVerifiedMiddlewareHelper(t *testing.T, tests []struct {
	name           string
	setupContext   func() core.Context
	userID         uint
	path           string
	expectedStatus int
}, createMiddleware func(core.Context) func(http.Handler) http.Handler) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coreCtx := tt.setupContext()
			middleware := createMiddleware(coreCtx)

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler := middleware(testHandler)

			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.userID > 0 {
				reqCtx := context.WithValue(req.Context(), mo.UserIDKey, tt.userID)
				req = req.WithContext(reqCtx)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status code %d, got %d", tt.expectedStatus, w.Code)
		})
	}
}

func TestAccountVerifiedMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() core.Context
		userID         uint
		path           string
		expectedStatus int
	}{
		{
			name: "valid verified user",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("IsAccountVerified", uint(1)).Return(true, nil)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				return ctx
			},
			userID:         1,
			path:           "/test",
			expectedStatus: http.StatusOK,
		},
		{
			name: "user not verified",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("IsAccountVerified", uint(2)).Return(false, nil)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				return ctx
			},
			userID:         2,
			path:           "/test",
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "error checking verification",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("IsAccountVerified", uint(3)).
					Return(false, errors.New("database error checking verification"))
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				return ctx
			},
			userID:         3,
			path:           "/test",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "no user in context",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				return ctx
			},
			userID:         0,
			path:           "/test",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	testAccountVerifiedMiddlewareHelper(t, tests, AccountVerifiedMiddleware)
}
