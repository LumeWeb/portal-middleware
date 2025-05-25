package swagger

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAndValidateSpec(t *testing.T) {
	t.Run("valid spec", func(t *testing.T) {
		mockSpec := []byte(`{
			"openapi": "3.0.0",
			"info": {
				"title": "Test API",
				"version": "1.0.0"
			},
			"paths": {}
		}`)

		_, err := LoadAndValidateSpec(mockSpec)
		require.NoError(t, err)
	})

	t.Run("invalid spec", func(t *testing.T) {
		invalidSpec := []byte(`{"invalid": "spec"}`)
		_, err := LoadAndValidateSpec(invalidSpec)
		require.Error(t, err)
	})
}

func TestWireRouter(t *testing.T) {
	t.Run("wires routes correctly", func(t *testing.T) {
		router := mux.NewRouter()
		err := WireRouter(router, "/api/spec.json", "/docs")
		require.NoError(t, err)
		
		tests := []struct {
			method string
			path   string
			status int
		}{
			{"GET", "/docs", http.StatusMovedPermanently},
			{"GET", "/docs/", http.StatusOK},
			{"GET", "/docs/swagger-initializer.js", http.StatusOK},
		}
		
		for _, tt := range tests {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.status, w.Code, "path: %s", tt.path)
		}
	})

	t.Run("invalid paths", func(t *testing.T) {
		router := mux.NewRouter()
		
		tests := []struct {
			name      string
			specPath  string
			uiPrefix  string
			expectErr string
		}{
			{
				name:      "empty spec path",
				specPath:  "",
				uiPrefix:  "/docs",
				expectErr: "specPath cannot be empty",
			},
			{
				name:      "empty ui prefix",
				specPath:  "/spec.json",
				uiPrefix:  "",
				expectErr: "uiPathPrefix must start with '/' and cannot be empty",
			},
			{
				name:      "ui prefix without slash",
				specPath:  "/spec.json",
				uiPrefix:  "docs",
				expectErr: "uiPathPrefix must start with '/' and cannot be empty",
			},
		}
		
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := WireRouter(router, tt.specPath, tt.uiPrefix)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			})
		}
	})
}

func TestNewHandler(t *testing.T) {
	mockSpec := []byte(`{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`)

	t.Run("wires UI routes correctly", func(t *testing.T) {
		router := mux.NewRouter()
		err := NewHandler(mockSpec, router)
		require.NoError(t, err)
		
		// Test UI routes instead of spec endpoint
		req := httptest.NewRequest("GET", "/swagger", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
		
		req = httptest.NewRequest("GET", "/swagger/", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	})
}

func TestNewStandaloneHandler(t *testing.T) {
	t.Run("creates valid handler", func(t *testing.T) {
		handler, err := NewStandaloneHandler("/api/spec.json", "/docs")
		require.NoError(t, err)
		
		tests := []struct {
			method string
			path   string
			status int
		}{
			{"GET", "/docs", http.StatusMovedPermanently},
			{"GET", "/docs/", http.StatusOK},
		}
		
		for _, tt := range tests {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.status, w.Code, "path: %s", tt.path)
		}
	})

	t.Run("propagates wire errors", func(t *testing.T) {
		_, err := NewStandaloneHandler("", "/docs")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "specPath cannot be empty")
	})
}
