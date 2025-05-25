package middleware

import (
	"github.com/stretchr/testify/assert"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/core/testing/mocks"
	"net/http"
	"testing"
)

func TestWithVerification(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {}
	ctx := coreTesting.NewTestContext(t)

	// Setup mock expectations
	mockUser := mocks.NewMockUserService(t)
	ctx.RegisterService(core.USER_SERVICE, mockUser)

	route := httputil.NewRoute("GET", "/test", handler, WithVerification(ctx))

	assert.Len(t, route.Middlewares, 1)
	mockUser.AssertExpectations(t)
}

func TestWith2FA(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {}
	ctx := mocks.NewMockContext(t)

	route := httputil.NewRoute("GET", "/test", handler, With2FA(ctx))

	assert.Len(t, route.Middlewares, 1)
}

func TestWithMiddleware(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {}
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	}

	route := httputil.NewRoute("GET", "/test", handler, WithMiddleware(mw))

	assert.Len(t, route.Middlewares, 1)
}
