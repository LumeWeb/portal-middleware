package tus

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/httputil"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-middleware/context"
	"go.lumeweb.com/portal/core/testing/mocks"
)

func TestJWTLocModifier(t *testing.T) {
	modifier := NewJWTLocModifier("auth")

	t.Run("adds token to query params", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/files", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.AuthTokenKey, "test-token"))

		modified := modifier.ModifyLocation("/12345", req)
		parsed, _ := url.Parse(modified)
		assert.Equal(t, "test-token", parsed.Query().Get("auth"))
	})

	t.Run("no token in context", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/files", nil)

		modified := modifier.ModifyLocation("/12345", req)
		assert.Equal(t, "/12345", modified)
	})

	t.Run("empty location", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/files", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.AuthTokenKey, "test-token"))

		modified := modifier.ModifyLocation("", req)
		assert.Equal(t, "", modified)
	})
}

func TestCorsMiddleware(t *testing.T) {
	handler := CorsMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("sets CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "upload-offset")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		headers := rr.Header()
		assert.Equal(t, "http://example.com", headers.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", headers.Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "GET", headers.Get("Access-Control-Allow-Methods"))
		assert.Contains(t, headers.Get("Access-Control-Allow-Headers"), "upload-offset")
	})

	t.Run("allows actual request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "http://example.com")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestTusResponseWriter(t *testing.T) {
	t.Run("modifies location header on 201", func(t *testing.T) {
		modifier := &mockModifier{location: "modified"}
		rr := httptest.NewRecorder()
		w := &tusResponseWriter{
			ResponseWriter:  rr,
			req:             httptest.NewRequest("POST", "/", nil),
			locationModifer: modifier,
		}

		w.Header().Set("Location", "original")
		w.WriteHeader(http.StatusCreated)

		assert.Equal(t, "modified", rr.Header().Get("Location"))
	})

	t.Run("doesnt modify other status codes", func(t *testing.T) {
		modifier := &mockModifier{location: "modified"}
		rr := httptest.NewRecorder()
		w := &tusResponseWriter{
			ResponseWriter:  rr,
			req:             httptest.NewRequest("GET", "/", nil),
			locationModifer: modifier,
		}

		w.Header().Set("Location", "original")
		w.WriteHeader(http.StatusFound)

		assert.Equal(t, "original", rr.Header().Get("Location"))
	})

	t.Run("preserves other headers", func(t *testing.T) {
		modifier := &mockModifier{location: "modified"}
		rr := httptest.NewRecorder()
		w := &tusResponseWriter{
			ResponseWriter:  rr,
			req:             httptest.NewRequest("POST", "/", nil),
			locationModifer: modifier,
		}

		w.Header().Set("X-Test", "value")
		w.Header().Set("Location", "original")
		w.WriteHeader(http.StatusCreated)

		assert.Equal(t, "value", rr.Header().Get("X-Test"))
	})

	t.Run("handles empty location header", func(t *testing.T) {
		modifier := &mockModifier{location: "modified"}
		rr := httptest.NewRecorder()
		w := &tusResponseWriter{
			ResponseWriter:  rr,
			req:             httptest.NewRequest("POST", "/", nil),
			locationModifer: modifier,
		}

		w.WriteHeader(http.StatusCreated)
		assert.Empty(t, rr.Header().Get("Location"))
	})
}

func TestPathMiddleware(t *testing.T) {
	basePath := "/files"
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/12345")
		w.WriteHeader(http.StatusCreated)
	})

	t.Run("strips base path and preserves query params", func(t *testing.T) {
		middleware := PathMiddleware(basePath, nil)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/files?test=1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)
		assert.Equal(t, "/", req.URL.Path)
		assert.Equal(t, "1", req.URL.Query().Get("test"))
	})

	t.Run("handles nested paths", func(t *testing.T) {
		middleware := PathMiddleware(basePath, nil)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/files/nested", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "/nested", req.URL.Path)
	})

	t.Run("handles empty path", func(t *testing.T) {
		middleware := PathMiddleware("", nil)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)
		assert.Equal(t, "/", req.URL.Path)
	})
}

type mockModifier struct {
	location string
}

func (m *mockModifier) ModifyLocation(loc string, r *http.Request) string {
	return m.location
}

type mockTUSHandler struct{}

func (h *mockTUSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRegisterTusRoutes(t *testing.T) {
	ctx := coreTesting.NewTestContext(t)
	mockRouter := mux.NewRouter()
	gRouter, err := httputil.NewSwaggerRouter(mockRouter, httputil.APIInfo().
		Title("TUS API").
		Version("1.0.0"))
	require.NoError(t, err)

	accessSvc := mocks.NewMockAccessService(t)
	accessSvc.EXPECT().CheckAccess(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	accessSvc.EXPECT().AssignRoleToUser(mock.Anything, mock.Anything).Return(nil).Maybe()
	accessSvc.EXPECT().RegisterRoute("test", "", "POST", "user").Return(nil).Once()
	accessSvc.EXPECT().RegisterRoute("test", "/{id}", "HEAD", "user").Return(nil).Once()
	accessSvc.EXPECT().RegisterRoute("test", "/{id}", "PATCH", "user").Return(nil).Once()
	accessSvc.EXPECT().RegisterRoute("test", "/{id}", "DELETE", "user").Return(nil).Once()
	basePath := "/files"
	tusHandler := &mockTUSHandler{}

	t.Run("registers all TUS methods", func(t *testing.T) {
		err := RegisterTusRoutes(ctx, gRouter, accessSvc, "test", basePath, tusHandler, false, false)
		assert.NoError(t, err)

		testCases := []struct {
			method string
			path   string
		}{
			{http.MethodPost, basePath},
			{http.MethodHead, basePath + "/123"},
			{http.MethodPatch, basePath + "/123"},
			{http.MethodDelete, basePath + "/123"},
			{http.MethodOptions, basePath},
		}

		for _, tc := range testCases {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()
			mockRouter.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "failed for %s %s", tc.method, tc.path)
		}
	})

	t.Run("applies auth when required", func(t *testing.T) {
		err := RegisterTusRoutes(ctx, gRouter, accessSvc, "test", basePath, tusHandler, true, false)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, basePath, nil)
		rr := httptest.NewRecorder()
		mockRouter.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("applies CORS headers", func(t *testing.T) {
		err := RegisterTusRoutes(ctx, gRouter, accessSvc, "test", basePath, tusHandler, false, false)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodOptions, basePath, nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rr := httptest.NewRecorder()
		mockRouter.ServeHTTP(rr, req)

		assert.Equal(t, "http://example.com", rr.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "POST", rr.Header().Get("Access-Control-Allow-Methods"))
	})

}
