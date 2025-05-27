package convert

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestUnwrap(t *testing.T) {
	t.Run("unwraps echo middleware correctly", func(t *testing.T) {
		echoMW := func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				c.Response().Header().Set("X-Test", "true")
				return next(c)
			}
		}

		httpMW := Unwrap(echoMW)

		handler := httpMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		}))

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "true", rec.Header().Get("X-Test"))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test", rec.Body.String())
	})

	t.Run("handles echo errors", func(t *testing.T) {
		echoMW := func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusBadRequest, "test error")
			}
		}

		httpMW := Unwrap(echoMW)

		handler := httpMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "test error")
	})
}

func TestHTTPHandler(t *testing.T) {
	t.Run("converts http.Handler to echo.HandlerFunc", func(t *testing.T) {
		httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", "true")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		})

		echoHandler := HTTPHandler(httpHandler)

		e := echo.New()
		e.GET("/", echoHandler)

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, "true", rec.Header().Get("X-Test"))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test", rec.Body.String())
	})
}

func TestHTTPHandlerFunc(t *testing.T) {
	t.Run("converts http.HandlerFunc to echo.HandlerFunc", func(t *testing.T) {
		httpHandler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", "true")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test"))
		}

		echoHandler := HTTPHandlerFunc(httpHandler)

		e := echo.New()
		e.GET("/", echoHandler)

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, "true", rec.Header().Get("X-Test"))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test", rec.Body.String())
	})
}
