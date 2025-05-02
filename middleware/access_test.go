package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func testAccessMiddlewareHelper(t *testing.T, tests []struct {
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

func TestAccessMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() core.Context
		userID         uint
		path           string
		expectedStatus int
	}{
		{
			name: "access granted",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
					Return(true, struct{ ID uint }{ID: 1}, nil)
				mockAccessSvc := coreMocks.NewMockAccessService(t)
				mockAccessSvc.On("CheckAccess", uint(1), mock.Anything, "/allowed", "GET").
					Return(true, nil)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)
				return ctx
			},
			userID:         1,
			path:           "/allowed",
			expectedStatus: http.StatusOK,
		},
		{
			name: "access denied",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
					Return(true, struct{ ID uint }{ID: 1}, nil)
				mockAccessSvc := coreMocks.NewMockAccessService(t)
				mockAccessSvc.On("CheckAccess", uint(1), mock.Anything, "/denied", "GET").
					Return(false, nil)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)
				return ctx
			},
			userID:         1,
			path:           "/denied",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "access error",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
					Return(true, struct{ ID uint }{ID: 1}, nil)
				mockAccessSvc := coreMocks.NewMockAccessService(t)
				mockAccessSvc.On("CheckAccess", uint(1), mock.Anything, "/error", "GET").
					Return(false, errors.New("permission check error"))
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)
				return ctx
			},
			userID:         1,
			path:           "/error",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "user does not exist",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1001)}).
					Return(false, nil, nil)
				mockAccessSvc := coreMocks.NewMockAccessService(t)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)
				return ctx
			},
			userID:         1001,
			path:           "/allowed",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "no user in context",
			setupContext: func() core.Context {
				ctx := coreTesting.NewTestContext(t)
				mockUserSvc := coreMocks.NewMockUserService(t)
				mockAccessSvc := coreMocks.NewMockAccessService(t)
				ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
				ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)
				return ctx
			},
			userID:         0,
			path:           "/allowed",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	testAccessMiddlewareHelper(t, tests, AccessMiddleware)
}
