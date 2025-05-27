package option

import (
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/portal-middleware/cors"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"testing"
)

func TestWithVerification(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	ctx := coreTesting.NewTestContext(t)

	// Setup mock expectations
	mockUser := mocks.NewMockUserService(t)
	ctx.RegisterService(core.USER_SERVICE, mockUser)

	route := router.NewRoute("GET", "/test", handler, WithVerification(ctx))

	assert.Len(t, route.Middlewares, 1)
	mockUser.AssertExpectations(t)
}

func TestWith2FA(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	ctx := mocks.NewMockContext(t)

	route := router.NewRoute("GET", "/test", handler, With2FA(ctx))

	assert.Len(t, route.Middlewares, 1)
}

func TestWithMiddleware(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	mw := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { return nil }
	}

	route := router.NewRoute("GET", "/test", handler, WithMiddleware(mw))

	assert.Len(t, route.Middlewares, 1)
}

func TestWithCORS(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	route := router.NewRoute("GET", "/test", handler, WithCORS())

	assert.Len(t, route.Middlewares, 1)
}

func TestWithCustomCORS(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	config := cors.Config{
		AllowedMethods: []string{"GET"},
	}
	route := router.NewRoute("GET", "/test", handler, WithCustomCORS(config))

	assert.Len(t, route.Middlewares, 1)
}

func TestWithTUSCORS(t *testing.T) {
	handler := func(c echo.Context) error { return nil }
	route := router.NewRoute("GET", "/test", handler, WithTUSCORS())

	assert.Len(t, route.Middlewares, 1)
}
