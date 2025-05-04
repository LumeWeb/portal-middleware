package adapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mo "go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type userTestCase struct {
	name        string
	userID      uint
	setupMock   func(*coreMocks.MockUserService)
	expectExist bool
	expectErr   bool
}

func testUserCheckerCases(t *testing.T, tests []userTestCase, testFunc func(*coreMocks.MockUserService, uint) (bool, error)) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := coreMocks.NewMockUserService(t)
			tt.setupMock(mockSvc)

			result, err := testFunc(mockSvc, tt.userID)

			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error: %v, got: %v", tt.expectErr, err)
			}
			if result != tt.expectExist {
				t.Errorf("Expected result: %v, got: %v", tt.expectExist, result)
			}
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestUserCheckerAccountExists(t *testing.T) {
	tests := []userTestCase{
		{
			name:   "user exists",
			userID: 1,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
					Return(true, struct{ ID uint }{ID: 1}, nil)
			},
			expectExist: true,
			expectErr:   false,
		},
		{
			name:   "user does not exist",
			userID: 999,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("Exists", mock.Anything, map[string]any{"id": uint(999)}).
					Return(false, nil, nil)
			},
			expectExist: false,
			expectErr:   false,
		},
		{
			name:   "error checking existence",
			userID: 1,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
					Return(false, nil, errors.New("database error"))
			},
			expectExist: false,
			expectErr:   true,
		},
	}

	testUserCheckerCases(t, tests, func(mockSvc *coreMocks.MockUserService, userID uint) (bool, error) {
		return NewUserChecker(mockSvc).AccountExists(userID)
	})
}

func TestUserCheckerIsAccountVerified(t *testing.T) {
	tests := []userTestCase{
		{
			name:   "account is verified",
			userID: 1,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("IsAccountVerified", uint(1)).Return(true, nil)
			},
			expectExist: true,
			expectErr:   false,
		},
		{
			name:   "account is not verified",
			userID: 2,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("IsAccountVerified", uint(2)).Return(false, nil)
			},
			expectExist: false,
			expectErr:   false,
		},
		{
			name:   "error checking verification",
			userID: 1,
			setupMock: func(mockSvc *coreMocks.MockUserService) {
				mockSvc.On("IsAccountVerified", uint(1)).Return(false, errors.New("database error"))
			},
			expectExist: false,
			expectErr:   true,
		},
	}

	testUserCheckerCases(t, tests, func(mockSvc *coreMocks.MockUserService, userID uint) (bool, error) {
		return NewUserChecker(mockSvc).IsAccountVerified(userID)
	})
}

type accessTestCase struct {
	name         string
	userID       uint
	host         string
	path         string
	method       string
	setupMock    func(service *coreMocks.MockAccessService)
	expectAccess bool
	expectErr    bool
}

func testAccessCheckerCases(t *testing.T, tests []accessTestCase) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := coreMocks.NewMockAccessService(t)
			tt.setupMock(mockSvc)

			checker := NewAccessChecker(mockSvc)
			access, err := checker.CheckAccess(tt.userID, tt.host, tt.path, tt.method)

			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error: %v, got: %v", tt.expectErr, err)
			}
			if access != tt.expectAccess {
				t.Errorf("Expected access: %v, got: %v", tt.expectAccess, access)
			}
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestAccessCheckerCheckAccess(t *testing.T) {
	tests := []accessTestCase{
		{
			name:   "access granted",
			userID: 1,
			host:   "example.com",
			path:   "/api/data",
			method: "GET",
			setupMock: func(mockSvc *coreMocks.MockAccessService) {
				mockSvc.On("CheckAccess", uint(1), "example.com", "/api/data", "GET").
					Return(true, nil)
			},
			expectAccess: true,
			expectErr:    false,
		},
		{
			name:   "access denied",
			userID: 2,
			host:   "example.com",
			path:   "/admin",
			method: "POST",
			setupMock: func(mockSvc *coreMocks.MockAccessService) {
				mockSvc.On("CheckAccess", uint(2), "example.com", "/admin", "POST").
					Return(false, nil)
			},
			expectAccess: false,
			expectErr:    false,
		},
		{
			name:   "error checking access",
			userID: 1,
			host:   "example.com",
			path:   "/api/data",
			method: "GET",
			setupMock: func(mockSvc *coreMocks.MockAccessService) {
				mockSvc.On("CheckAccess", uint(1), "example.com", "/api/data", "GET").
					Return(false, errors.New("permission error"))
			},
			expectAccess: false,
			expectErr:    true,
		},
	}

	testAccessCheckerCases(t, tests)
}

func TestNewUserCheckerFromCore(t *testing.T) {
	// Create a testing context
	ctx := coreTesting.NewTestContext(t)

	// Create mockery-generated mock
	mockUserSvc := coreMocks.NewMockUserService(t)

	// Set up expectations
	mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
		Return(true, struct{ ID uint }{ID: 1}, nil)
	mockUserSvc.On("IsAccountVerified", uint(1)).Return(true, nil)

	// Register the mock service with the testing context
	ctx.RegisterService(core.USER_SERVICE, mockUserSvc)

	// Create the checker from the context
	checker := NewUserCheckerFromCore(ctx)

	// Verify checker was created
	require.NotNil(t, checker, "Expected non-nil UserChecker")

	// Test the checker
	exists, err := checker.AccountExists(1)
	require.NoError(t, err, "Unexpected error checking account existence")
	require.True(t, exists, "Expected AccountExists to return true")

	verified, err := checker.IsAccountVerified(1)
	require.NoError(t, err, "Unexpected error checking account verification")
	require.True(t, verified, "Expected IsAccountVerified to return true")

	// Verify all expectations were met
	mockUserSvc.AssertExpectations(t)
}

func TestNewAccessCheckerFromCore(t *testing.T) {
	// Create a testing context
	ctx := coreTesting.NewTestContext(t)

	// Create mockery-generated mock
	mockAccessSvc := coreMocks.NewMockAccessService(t)

	// Set up expectations
	mockAccessSvc.On("CheckAccess", uint(1), "example.com", "/api", "GET").
		Return(true, nil)

	// Register the mock service with the testing context
	ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)

	// Create the checker from the context
	checker := NewAccessCheckerFromCore(ctx)

	// Verify checker was created
	require.NotNil(t, checker, "Expected non-nil AccessChecker")

	// Test the checker
	access, err := checker.CheckAccess(1, "example.com", "/api", "GET")
	require.NoError(t, err, "Unexpected error checking access")
	require.True(t, access, "Expected CheckAccess to return true")

	// Verify all expectations were met
	mockAccessSvc.AssertExpectations(t)
}

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
