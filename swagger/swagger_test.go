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
	mockJSON := []byte(`{"test":"spec"}`)

	t.Run("wires routes correctly", func(t *testing.T) {
		router := mux.NewRouter()
		WireRouter(mockJSON, router)
		
		tests := []struct {
			method string
			path   string
			status int
		}{
			{"GET", "/swagger.json", http.StatusOK},
			{"GET", "/swagger", http.StatusMovedPermanently},
			{"GET", "/swagger/", http.StatusOK},
		}
		
		for _, tt := range tests {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.status, w.Code, "path: %s", tt.path)
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

	t.Run("wires routes correctly", func(t *testing.T) {
		router := mux.NewRouter()
		err := NewHandler(mockSpec, router)
		require.NoError(t, err)
		
		req := httptest.NewRequest("GET", "/swagger.json", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

func TestNewStandaloneHandler(t *testing.T) {
	mockSpec := []byte(`{
		"openapi": "3.0.0",
		"info": {
			"title": "Test API",
			"version": "1.0.0"
		},
		"paths": {}
	}`)

	t.Run("creates valid handler", func(t *testing.T) {
		handler, err := NewStandaloneHandler(mockSpec)
		require.NoError(t, err)
		
		req := httptest.NewRequest("GET", "/swagger.json", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}
