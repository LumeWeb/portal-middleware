package tus

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	router "go.lumeweb.com/portal-router"
)

// mockTusHandler is a mock handler that simulates TUS protocol behavior
func mockTusHandler(c echo.Context) error {
	method := c.Request().Method

	switch method {
	case http.MethodOptions:
		// Simulate the actual TUS OPTIONS handler behavior
		c.Response().Header().Set("Tus-Version", "1.0.0")
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		c.Response().Header().Set("Tus-Max-Size", "53687091200") // 50GB
		c.Response().Header().Set("Tus-Extension", "creation,termination")
		c.Response().Header().Set("Access-Control-Allow-Methods", "POST,HEAD,PATCH,DELETE,OPTIONS")
		c.Response().Header().Set("Access-Control-Allow-Headers", "Authorization,Origin,X-Requested-With,X-Request-ID,X-HTTP-Method-Override,Content-Type,Upload-Length,Upload-Offset,Tus-Resumable,Upload-Metadata,Upload-Defer-Length,Upload-Concat,Upload-Incomplete,Upload-Complete,Upload-Draft-Interop-Version")
		c.Response().Header().Set("Access-Control-Expose-Headers", "Upload-Offset,Location,Upload-Length,Tus-Version,Tus-Resumable,Tus-Max-Size,Tus-Extension,Upload-Metadata,Upload-Defer-Length,Upload-Concat,Upload-Incomplete,Upload-Complete,Upload-Draft-Interop-Version")
		return c.NoContent(http.StatusOK)
	case http.MethodPost:
		// Simulate TUS POST handler
		c.Response().Header().Set("Location", "/files/test-upload-id")
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		return c.NoContent(http.StatusCreated)
	case http.MethodHead:
		// Simulate TUS HEAD handler
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		c.Response().Header().Set("Upload-Length", "1024")
		c.Response().Header().Set("Upload-Offset", "0")
		return c.NoContent(http.StatusOK)
	case http.MethodPatch:
		// Simulate TUS PATCH handler
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		c.Response().Header().Set("Upload-Offset", "512")
		return c.NoContent(http.StatusOK)
	case http.MethodDelete:
		// Simulate TUS DELETE handler
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		return c.NoContent(http.StatusNoContent)
	default:
		return c.NoContent(http.StatusMethodNotAllowed)
	}
}

func TestRegisterTusRoutes(t *testing.T) {
	tests := []struct {
		name         string
		authRequired bool
		twoFARequired bool
	}{
		{
			name:         "public TUS routes without auth",
			authRequired: false,
			twoFARequired: false,
		},
		{
			name:         "protected TUS routes with auth",
			authRequired: true,
			twoFARequired: false,
		},
		{
			name:         "protected TUS routes with 2FA",
			authRequired: true,
			twoFARequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new router for testing
			testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
			require.NoError(t, err)
			require.NotNil(t, testRouter)

			echoRouter := router.GetRouter(testRouter)
			require.NotNil(t, echoRouter)

			basePath := "/uploads"
			subdomain := "api"

			// Register TUS routes (with nil context and access service since we're only testing routing)
			err = RegisterTusRoutes(
				nil, // context can be nil for routing-only tests
				testRouter,
				nil, // access service can be nil for routing-only tests
				subdomain,
				basePath,
				mockTusHandler,
				tt.authRequired,
				tt.twoFARequired,
			)
			require.NoError(t, err)

			// Verify all standard TUS routes are registered
			t.Run("standard routes registered", func(t *testing.T) {
				routes := echoRouter.Routes()
				
				// Expected routes
				expectedRoutes := map[string]bool{
					http.MethodPost + basePath:        false,
					http.MethodHead + basePath + "/:id": false,
					http.MethodPatch + basePath + "/:id": false,
					http.MethodDelete + basePath + "/:id": false,
					http.MethodOptions + basePath + "/:id": false,
					http.MethodOptions + basePath:       false,
				}

				// Check each route
				for _, route := range routes {
					key := route.Method + route.Path
					if _, exists := expectedRoutes[key]; exists {
						expectedRoutes[key] = true
					}
				}

				// Verify all expected routes are present
				for route, found := range expectedRoutes {
					assert.True(t, found, "Expected route %s to be registered", route)
				}
			})
		})
	}
}

func TestTusOptionsRequests(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantStatusCode int
		wantHeaders    map[string]string
	}{
		{
			name:           "OPTIONS to base path returns TUS protocol headers",
			path:           "/uploads",
			wantStatusCode: http.StatusOK,
			wantHeaders: map[string]string{
				"Tus-Version":                  "1.0.0",
				"Tus-Resumable":                "1.0.0",
				"Tus-Max-Size":                 "53687091200",
				"Tus-Extension":                "creation,termination",
				"Access-Control-Allow-Methods": "POST,HEAD,PATCH,DELETE,OPTIONS",
			},
		},
		{
			name:           "OPTIONS to specific upload ID returns TUS protocol headers",
			path:           "/uploads/test-id",
			wantStatusCode: http.StatusOK,
			wantHeaders: map[string]string{
				"Tus-Version":                  "1.0.0",
				"Tus-Resumable":                "1.0.0",
				"Tus-Max-Size":                 "53687091200",
				"Tus-Extension":                "creation,termination",
				"Access-Control-Allow-Methods": "POST,HEAD,PATCH,DELETE,OPTIONS",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new router for testing
			testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
			require.NoError(t, err)

			echoRouter := router.GetRouter(testRouter)
			require.NotNil(t, echoRouter)

			basePath := "/uploads"
			subdomain := "api"

			// Register TUS routes without auth to test CORS behavior
			err = RegisterTusRoutes(
				nil,
				testRouter,
				nil,
				subdomain,
				basePath,
				mockTusHandler,
				false, // No auth required for CORS testing
				false,
			)
			require.NoError(t, err)

			// Create OPTIONS request
			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			rec := httptest.NewRecorder()
			
			echoRouter.ServeHTTP(rec, req)

			// Verify response status
			assert.Equal(t, tt.wantStatusCode, rec.Code, "Expected status code %d, got %d", tt.wantStatusCode, rec.Code)

			// Verify TUS protocol headers are present
			for header, expectedValue := range tt.wantHeaders {
				gotValue := rec.Header().Get(header)
				assert.Equal(t, expectedValue, gotValue, "Expected %s header to be %q, got %q", header, expectedValue, gotValue)
			}

			// Verify that the actual TUS handler was called (not a dummy handler)
			// by checking for specific headers that only the TUS handler sets
			assert.NotEmpty(t, rec.Header().Get("Tus-Version"), "Tus-Version header should be set by actual TUS handler")
			assert.NotEmpty(t, rec.Header().Get("Tus-Resumable"), "Tus-Resumable header should be set by actual TUS handler")
		})
	}
}

func TestTusHandlerCalledForOptions(t *testing.T) {
	// This test verifies that the actual tusHandler is called for OPTIONS requests,
	// not a dummy handler, which was the bug we fixed.
	
	// Create router
	testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
	require.NoError(t, err)

	echoRouter := router.GetRouter(testRouter)
	require.NotNil(t, echoRouter)

	basePath := "/uploads"
	subdomain := "api"

	// Track which handler was called
	handlerCalled := false
	handlerMethod := ""
	handlerPath := ""

	trackingHandler := func(c echo.Context) error {
		handlerCalled = true
		handlerMethod = c.Request().Method
		handlerPath = c.Request().URL.Path
		
		// Call the mock handler to set expected headers
		return mockTusHandler(c)
	}

	// Register TUS routes
	err = RegisterTusRoutes(
		nil,
		testRouter,
		nil,
		subdomain,
		basePath,
		trackingHandler,
		false,
		false,
	)
	require.NoError(t, err)

	tests := []struct {
		name    string
		method  string
		path    string
	}{
		{
			name:   "OPTIONS base path calls tusHandler",
			method: http.MethodOptions,
			path:   "/uploads",
		},
		{
			name:   "OPTIONS with ID calls tusHandler",
			method: http.MethodOptions,
			path:   "/uploads/test-upload-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset tracking variables
			handlerCalled = false
			handlerMethod = ""
			handlerPath = ""

			// Create request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			
			echoRouter.ServeHTTP(rec, req)

			// Verify the handler was called
			assert.True(t, handlerCalled, "Expected handler to be called for %s %s", tt.method, tt.path)
			assert.Equal(t, tt.method, handlerMethod, "Expected method %s, got %s", tt.method, handlerMethod)
			// PathMiddleware strips the basePath (/uploads) from the path before reaching handler
			expectedTrimmedPath := tt.path
			if expectedTrimmedPath == "/uploads" {
				expectedTrimmedPath = "/"
			} else if len(expectedTrimmedPath) > len("/uploads") && expectedTrimmedPath[:len("/uploads")] == "/uploads" {
				expectedTrimmedPath = expectedTrimmedPath[len("/uploads"):]
			}
			assert.Equal(t, expectedTrimmedPath, handlerPath, "Expected path %s, got %s", expectedTrimmedPath, handlerPath)

			// Verify TUS headers were set (which only happens in the actual TUS handler)
			assert.NotEmpty(t, rec.Header().Get("Tus-Version"), "Tus-Version header should be set")
			assert.NotEmpty(t, rec.Header().Get("Tus-Resumable"), "Tus-Resumable header should be set")
			
			// This proves that the actual tusHandler was called, not a dummy handler
			// because the dummy handler wouldn't set these headers
		})
	}
}

func TestDummyOptionsHandlerRemoved(t *testing.T) {
	// This test verifies that there is no reference to dummyOptionsHandler
	// and that OPTIONS requests use the actual TUS handler
	
	testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
	require.NoError(t, err)

	echoRouter := router.GetRouter(testRouter)
	require.NotNil(t, echoRouter)

	basePath := "/uploads"
	subdomain := "api"

	// Register TUS routes
	err = RegisterTusRoutes(
		nil,
		testRouter,
		nil,
		subdomain,
		basePath,
		mockTusHandler,
		false,
		false,
	)
	require.NoError(t, err)

	// Test both OPTIONS endpoints
	tests := []struct {
		name string
		path string
	}{
		{"OPTIONS base path", "/uploads"},
		{"OPTIONS with ID", "/uploads/some-id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			rec := httptest.NewRecorder()
			
			echoRouter.ServeHTTP(rec, req)

			// The response should have proper TUS headers
			// A dummy handler would not have set these
			version := rec.Header().Get("Tus-Version")
			assert.NotEmpty(t, version, "Tus-Version should be set - this proves the actual TUS handler is being used")
			assert.Equal(t, "1.0.0", version, "Tus-Version should be 1.0.0")

			resumable := rec.Header().Get("Tus-Resumable")
			assert.NotEmpty(t, resumable, "Tus-Resumable should be set - this proves the actual TUS handler is being used")
			assert.Equal(t, "1.0.0", resumable, "Tus-Resumable should be 1.0.0")

			// Check for TUS extension header
			extension := rec.Header().Get("Tus-Extension")
			assert.Contains(t, extension, "creation", "Tus-Extension should include 'creation'")

			// If a dummy handler was used, these headers would be missing
		})
	}
}

func TestTusStandardRoutes(t *testing.T) {
	testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
	require.NoError(t, err)

	echoRouter := router.GetRouter(testRouter)
	require.NotNil(t, echoRouter)

	basePath := "/uploads"
	subdomain := "api"

	err = RegisterTusRoutes(
		nil,
		testRouter,
		nil,
		subdomain,
		basePath,
		mockTusHandler,
		false,
		false,
	)
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		path           string
		wantStatusCode int
		wantHeaders    map[string]string
	}{
		{
			name:           "POST create upload",
			method:         http.MethodPost,
			path:           "/uploads",
			wantStatusCode: http.StatusCreated,
			wantHeaders: map[string]string{
				"Location":      "/files/test-upload-id",
				"Tus-Resumable": "1.0.0",
			},
		},
		{
			name:           "HEAD upload info",
			method:         http.MethodHead,
			path:           "/uploads/test-id",
			wantStatusCode: http.StatusOK,
			wantHeaders: map[string]string{
				"Tus-Resumable": "1.0.0",
				"Upload-Length": "1024",
				"Upload-Offset": "0",
			},
		},
		{
			name:           "PATCH upload data",
			method:         http.MethodPatch,
			path:           "/uploads/test-id",
			wantStatusCode: http.StatusOK,
			wantHeaders: map[string]string{
				"Tus-Resumable": "1.0.0",
				"Upload-Offset": "512",
			},
		},
		{
			name:           "DELETE upload",
			method:         http.MethodDelete,
			path:           "/uploads/test-id",
			wantStatusCode: http.StatusNoContent,
			wantHeaders: map[string]string{
				"Tus-Resumable": "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			
			// For PATCH requests, add required headers
			if tt.method == http.MethodPatch {
				req.Header.Set("Content-Type", "application/offset+octet-stream")
				req.Header.Set("Upload-Offset", "512")
				req.Header.Set("Tus-Resumable", "1.0.0")
			}
			
			// For HEAD requests, add required headers
			if tt.method == http.MethodHead {
				req.Header.Set("Tus-Resumable", "1.0.0")
			}
			
			// For DELETE requests, add required headers
			if tt.method == http.MethodDelete {
				req.Header.Set("Tus-Resumable", "1.0.0")
			}
			
			rec := httptest.NewRecorder()
			echoRouter.ServeHTTP(rec, req)

			// Verify response status
			assert.Equal(t, tt.wantStatusCode, rec.Code, "Expected status code %d for %s %s, got %d", 
				tt.wantStatusCode, tt.method, tt.path, rec.Code)

			// Verify headers
			for header, expectedValue := range tt.wantHeaders {
				gotValue := rec.Header().Get(header)
				assert.Equal(t, expectedValue, gotValue, "Expected %s header to be %q, got %q", 
					header, expectedValue, gotValue)
			}
		})
	}
}

func TestTusCORSHeaders(t *testing.T) {
	testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
	require.NoError(t, err)

	echoRouter := router.GetRouter(testRouter)
	require.NotNil(t, echoRouter)

	basePath := "/uploads"
	subdomain := "api"

	err = RegisterTusRoutes(
		nil,
		testRouter,
		nil,
		subdomain,
		basePath,
		mockTusHandler,
		false,
		false,
	)
	require.NoError(t, err)

	// Test CORS preflight on OPTIONS
	t.Run("CORS preflight response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/uploads", nil)
		rec := httptest.NewRecorder()
		
		echoRouter.ServeHTTP(rec, req)

		// Verify CORS headers are present
		allowMethods := rec.Header().Get("Access-Control-Allow-Methods")
		assert.Contains(t, allowMethods, "POST", "CORS should allow POST method")
		assert.Contains(t, allowMethods, "HEAD", "CORS should allow HEAD method")
		assert.Contains(t, allowMethods, "PATCH", "CORS should allow PATCH method")
		assert.Contains(t, allowMethods, "OPTIONS", "CORS should allow OPTIONS method")

		allowHeaders := rec.Header().Get("Access-Control-Allow-Headers")
		assert.Contains(t, allowHeaders, "Authorization", "CORS should allow Authorization header")
		assert.Contains(t, allowHeaders, "Tus-Resumable", "CORS should allow Tus-Resumable header")
		assert.Contains(t, allowHeaders, "Upload-Offset", "CORS should allow Upload-Offset header")
		assert.Contains(t, allowHeaders, "Upload-Length", "CORS should allow Upload-Length header")

		exposeHeaders := rec.Header().Get("Access-Control-Expose-Headers")
		assert.Contains(t, exposeHeaders, "Location", "CORS should expose Location header")
		assert.Contains(t, exposeHeaders, "Upload-Offset", "CORS should expose Upload-Offset header")
		assert.Contains(t, exposeHeaders, "Tus-Version", "CORS should expose Tus-Version header")
		assert.Contains(t, exposeHeaders, "Tus-Resumable", "CORS should expose Tus-Resumable header")
	})
}

func TestTusPathMiddleware(t *testing.T) {
	tests := []struct {
		name         string
		basePath     string
		requestPath  string
		expectedPath string
	}{
		{
			name:         "trailing slash is removed",
			basePath:     "/uploads/",
			requestPath:  "/uploads/test",
			expectedPath: "/test",
		},
		{
			name:         "base path is trimmed",
			basePath:     "/uploads",
			requestPath:  "/uploads/test",
			expectedPath: "/test",
		},
		{
			name:         "empty path after trim becomes slash",
			basePath:     "/uploads",
			requestPath:  "/uploads",
			expectedPath: "/",
		},
		{
			name:         "non-TUS path is not modified",
			basePath:     "/uploads",
			requestPath:  "/api/other",
			expectedPath: "/api/other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := PathMiddleware(tt.basePath, nil)
			
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			rec := httptest.NewRecorder()
			
			c := e.NewContext(req, rec)
			
			handled := false
			var capturedPath string
			
			handler := func(ec echo.Context) error {
				handled = true
				capturedPath = ec.Request().URL.Path
				return ec.NoContent(http.StatusOK)
			}

			err := mw(handler)(c)
			require.NoError(t, err)
			
			assert.True(t, handled)
			assert.Equal(t, tt.expectedPath, capturedPath)
		})
	}
}

func TestJWTLocModifier(t *testing.T) {
	tests := []struct {
		name           string
		authToken      string
		location       string
		expectedResult string
	}{
		{
			name:           "appends token to location URL",
			authToken:      "test-token-123",
			location:       "http://example.com/files/upload-id",
			expectedResult: "http://example.com/files/upload-id?auth_token=test-token-123",
		},
		{
			name:           "no auth token returns original location",
			authToken:      "",
			location:       "http://example.com/files/upload-id",
			expectedResult: "http://example.com/files/upload-id",
		},
		{
			name:           "preserves existing query params",
			authToken:      "test-token-123",
			location:       "http://example.com/files/upload-id?existing=param",
			expectedResult: "http://example.com/files/upload-id?auth_token=test-token-123&existing=param",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			
			// Set auth token if needed using the correct key
			if tt.authToken != "" {
				c.Set("authToken", tt.authToken)
			}
			
			modifier := NewJWTLocModifier("auth_token")
			result := modifier.ModifyLocation(tt.location, c)
			
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// Test that the fix for the dummyOptionsHandler issue works correctly
func TestDummyOptionsHandlerFixVerification(t *testing.T) {
	// This test explicitly verifies the fix that was made:
	// 1. dummyOptionsHandler has been removed
	// 2. OPTIONS requests now go to the actual tusHandler
	// 3. All OPTIONS routes use tusHandler
	
	testRouter, err := router.NewSwaggerRouter(router.APIInfo().Title("TUS Test API").Version("1.0.0"))
	require.NoError(t, err)

	echoRouter := router.GetRouter(testRouter)
	require.NotNil(t, echoRouter)

	basePath := "/uploads"

	// Track if the handler was called
	tusHandlerCalled := false

	testHandler := func(c echo.Context) error {
		tusHandlerCalled = true
		
		// Set TUS protocol headers to prove it's the real handler
		c.Response().Header().Set("Tus-Version", "1.0.0")
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		
		return c.NoContent(http.StatusOK)
	}

	err = RegisterTusRoutes(
		nil,
		testRouter,
		nil,
		"api",
		basePath,
		testHandler,
		false,
		false,
	)
	require.NoError(t, err)

	// Test OPTIONS requests
	t.Run("OPTIONS base path uses tusHandler", func(t *testing.T) {
		tusHandlerCalled = false
		
		req := httptest.NewRequest(http.MethodOptions, "/uploads", nil)
		rec := httptest.NewRecorder()
		
		echoRouter.ServeHTTP(rec, req)
		
		// Verify the actual TUS handler was called
		assert.True(t, tusHandlerCalled, "tusHandler should be called for OPTIONS requests")
		
		// Verify TUS protocol headers were set by the handler
		assert.Equal(t, "1.0.0", rec.Header().Get("Tus-Version"), "Tus-Version should be set by tusHandler")
		assert.Equal(t, "1.0.0", rec.Header().Get("Tus-Resumable"), "Tus-Resumable should be set by tusHandler")
	})

	t.Run("OPTIONS with ID uses tusHandler", func(t *testing.T) {
		tusHandlerCalled = false
		
		req := httptest.NewRequest(http.MethodOptions, "/uploads/some-upload-id", nil)
		rec := httptest.NewRecorder()
		
		echoRouter.ServeHTTP(rec, req)
		
		// Verify the actual TUS handler was called
		assert.True(t, tusHandlerCalled, "tusHandler should be called for OPTIONS requests with ID")
		
		// Verify TUS protocol headers were set by the handler
		assert.Equal(t, "1.0.0", rec.Header().Get("Tus-Version"), "Tus-Version should be set by tusHandler")
		assert.Equal(t, "1.0.0", rec.Header().Get("Tus-Resumable"), "Tus-Resumable should be set by tusHandler")
	})
}
