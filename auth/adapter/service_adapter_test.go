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
	// Create a testing context
	ctx := coreTesting.NewTestContext(t)

	// Create mockery-generated mocks
	mockUserSvc := coreMocks.NewMockUserService(t)
	mockAccessSvc := coreMocks.NewMockAccessService(t)

	// Set up user service expectations for the request with user ID
	mockUserSvc.On("Exists", mock.Anything, map[string]any{"id": uint(1)}).
		Return(true, struct{ ID uint }{ID: 1}, nil)
	mockAccessSvc.On("CheckAccess", uint(1), mock.Anything, mock.Anything, "GET").
		Return(true, nil)

	// Register services with the testing context
	ctx.RegisterService(core.USER_SERVICE, mockUserSvc)
	ctx.RegisterService(core.ACCESS_SERVICE, mockAccessSvc)

	// Create the middleware
	middleware := NewAccessMiddlewareFromCore(ctx)
	require.NotNil(t, middleware, "Expected non-nil middleware function")

	// Create a test handler that the middleware will wrap
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Apply the middleware to the test handler
	handler := middleware(testHandler)

	// Test 1: Request without user ID in context
	req := httptest.NewRequest("GET", "/api", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should fail with unauthorized
	assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected unauthorized status when no user ID in context")

	// Test 2: Request with user ID in context
	req = httptest.NewRequest("GET", "/api", nil)
	reqCtx := req.Context()
	reqCtx = context.WithValue(reqCtx, mo.UserIDKey, uint(1))
	req = req.WithContext(reqCtx)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should succeed now
	assert.Equal(t, http.StatusOK, w.Code, "Expected OK status when user ID in context and access granted")

	// Verify all expectations were met
	mockUserSvc.AssertExpectations(t)
	mockAccessSvc.AssertExpectations(t)
}
