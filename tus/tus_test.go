package tus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/context"
)

func TestPathMiddleware(t *testing.T) {
	basePath := "/files"
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject any request not at root path
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "/12345")
		w.WriteHeader(http.StatusCreated)
	})

	t.Run("strips base path", func(t *testing.T) {
		middleware := PathMiddleware(basePath, nil)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/files", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)
		assert.Equal(t, "/", req.URL.Path)
		assert.Equal(t, "/12345", rr.Header().Get("Location"))
	})

	t.Run("modifies location header", func(t *testing.T) {
		modifier := NewJWTLocModifier("token")
		middleware := PathMiddleware(basePath, modifier)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/files", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.AuthTokenKey, "test-token"))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		location := rr.Header().Get("Location")
		assert.Contains(t, location, "?token=test-token")
	})

	t.Run("ignores non-matching paths", func(t *testing.T) {
		middleware := PathMiddleware(basePath, nil)
		handler := middleware(testHandler)

		req := httptest.NewRequest("POST", "/other", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "/other", req.URL.Path)
	})
}

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

func TestLocationModifierResponseWriter(t *testing.T) {
	t.Run("modifies location header on 201", func(t *testing.T) {
		modifier := &mockModifier{location: "modified"}
		rr := httptest.NewRecorder()
		w := &locationModifierResponseWriter{
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
		w := &locationModifierResponseWriter{
			ResponseWriter:  rr,
			req:             httptest.NewRequest("GET", "/", nil),
			locationModifer: modifier,
		}

		w.Header().Set("Location", "original")
		w.WriteHeader(http.StatusFound)

		assert.Equal(t, "original", rr.Header().Get("Location"))
	})
}

type mockModifier struct {
	location string
}

func (m *mockModifier) ModifyLocation(loc string, r *http.Request) string {
	return m.location
}
