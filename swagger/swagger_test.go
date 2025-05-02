package swagger

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	mockSpec := []byte(`{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`)

	t.Run("serves swagger.json", func(t *testing.T) {
		handler := NewHandler(mockSpec, "/docs")
		
		req := httptest.NewRequest("GET", "/docs/swagger.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.JSONEq(t, string(mockSpec), w.Body.String())
	})

	t.Run("serves swagger UI", func(t *testing.T) {
		handler := NewHandler(mockSpec, "/docs")
		
		req := httptest.NewRequest("GET", "/docs/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	})

	t.Run("handles invalid spec", func(t *testing.T) {
		invalidSpec := []byte(`{"invalid": "spec"}`)
		handler := NewHandler(invalidSpec, "/docs")
		
		req := httptest.NewRequest("GET", "/docs/swagger.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles base path stripping", func(t *testing.T) {
		handler := NewHandler(mockSpec, "/api/docs")
		
		req := httptest.NewRequest("GET", "/api/docs/swagger.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandlerValidation(t *testing.T) {
	t.Run("returns valid OpenAPI document", func(t *testing.T) {
		spec := []byte(`{
			"openapi": "3.0.0",
			"info": {
				"title": "Valid API",
				"version": "1.0.0"
			},
			"paths": {}
		}`)
		
		handler := NewHandler(spec, "/docs")
		req := httptest.NewRequest("GET", "/docs/swagger.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		loader := openapi3.NewLoader()
		_, err := loader.LoadFromData(w.Body.Bytes())
		require.NoError(t, err, "Should produce valid OpenAPI spec")
	})
}
