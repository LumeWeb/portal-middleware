package convert

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// Wrap converts a standard http.Handler middleware to an echo.MiddlewareFunc.
// It properly propagates errors from the echo handler chain.
func Wrap(mw func(http.Handler) http.Handler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var handlerErr error
			
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				handlerErr = next(c)
			}))
			
			handler.ServeHTTP(c.Response(), c.Request())
			return handlerErr
		}
	}
}

// Unwrap converts an echo.MiddlewareFunc to a standard http.Handler middleware.
func Unwrap(mw echo.MiddlewareFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e := echo.New()
			c := e.NewContext(r, w)
			
			handler := mw(func(c echo.Context) error {
				next.ServeHTTP(c.Response(), c.Request())
				return nil
			})
			
			// Execute the middleware chain and handle any errors
			if err := handler(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
		})
	}
}

// HTTPHandler converts a standard http.Handler to an echo.HandlerFunc.
func HTTPHandler(h http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// HTTPHandlerFunc converts a standard http.HandlerFunc to an echo.HandlerFunc.
func HTTPHandlerFunc(h http.HandlerFunc) echo.HandlerFunc {
	return HTTPHandler(h)
}
