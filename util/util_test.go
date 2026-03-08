package util

import (
	"context"
	"go.lumeweb.com/portal-middleware/cors"
	"go.sia.tech/coreutils/wallet"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coreTesting "go.lumeweb.com/portal/core/testing"
)

func TestMiddlewareChain(t *testing.T) {
	t.Run("basic chain", func(t *testing.T) {
		baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		mw := New(baseHandler).
			Chain(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Test", "true")
					next.ServeHTTP(w, r)
				})
			})

		req := httptest.NewRequest("OPTIONS", "/", nil)
		rr := httptest.NewRecorder()
		mw.Then().ServeHTTP(rr, req)

		assert.Equal(t, "true", rr.Header().Get("X-Test"))
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("with auth middleware", func(t *testing.T) {
		testCtx, err := coreTesting.NewTestContext(t)
		require.NoError(t, err)

		seedPhrase := wallet.NewSeedPhrase()

		// Set domain
		err = testCtx.Config().Set(context.Background(), "core.domain", "test.com")
		if err != nil {
			t.Error(err)
		}

		// Set seed
		err = testCtx.Config().Set(context.Background(), "core.identity", seedPhrase)
		if err != nil {
			t.Error(err)
		}

		baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		mw := New(baseHandler).
			WithAuthFromCore(testCtx, "test")

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		mw.Then().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("with CORS middleware", func(t *testing.T) {
		baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		mw := New(baseHandler).WithCORS(cors.Config{
			AllowedMethods: []string{"GET"},
		})

		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rr := httptest.NewRecorder()
		mw.Then().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Methods"))
	})

	t.Run("then returns handler", func(t *testing.T) {
		baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		mw := New(baseHandler)
		handler := mw.Then()

		assert.NotNil(t, handler)
		assert.IsType(t, http.HandlerFunc(nil), handler)
	})
}
