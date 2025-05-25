package tus

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-middleware/auth/adapter"
	"go.lumeweb.com/portal-middleware/auth/jwt"
	router "go.lumeweb.com/portal-router"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.sia.tech/coreutils/wallet"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.lumeweb.com/portal-middleware/context"
	coreMocks "go.lumeweb.com/portal/core/testing/mocks"
)

func TestJWTLocModifier(t *testing.T) {
	modifier := NewJWTLocModifier("auth")

	t.Run("adds token to query params", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest("POST", "/files", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set(string(mcontext.AuthTokenKey), "test-token")

		modified := modifier.ModifyLocation("/12345", c)
		parsed, _ := url.Parse(modified)
		assert.Equal(t, "test-token", parsed.Query().Get("auth"))
	})

	t.Run("no token in context", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest("POST", "/files", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		modified := modifier.ModifyLocation("/12345", c)
		assert.Equal(t, "/12345", modified)
	})

	t.Run("empty location", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest("POST", "/files", nil)
		req = req.WithContext(context.WithValue(req.Context(), mcontext.AuthTokenKey, "test-token"))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		modified := modifier.ModifyLocation("", c)
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

func TestPathMiddleware(t *testing.T) {
	basePath := "/files"

	// Setup test handler that will be wrapped by middleware
	testHandler := func(c echo.Context) error {
		if c.Request().URL.Path != "/" {
			return c.NoContent(http.StatusBadRequest)
		}
		c.Response().Header().Set("Location", "/12345")
		return c.NoContent(http.StatusCreated)
	}

	t.Run("strips base path and preserves query params", func(t *testing.T) {
		e := echo.New()
		e.Use(PathMiddleware(basePath, nil))
		e.POST("/files", testHandler)

		req := httptest.NewRequest(http.MethodPost, "/files?test=1", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "/12345", rec.Header().Get("Location"))
	})

	t.Run("handles nested paths", func(t *testing.T) {
		e := echo.New()
		e.Use(PathMiddleware(basePath, nil))
		e.POST("/files/nested", testHandler)

		req := httptest.NewRequest(http.MethodPost, "/files/nested", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("handles empty path", func(t *testing.T) {
		e := echo.New()
		e.Use(PathMiddleware("", nil))
		e.POST("/", testHandler)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "/12345", rec.Header().Get("Location"))
	})

	t.Run("modifies location header with auth token", func(t *testing.T) {
		e := echo.New()
		e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				c.Set(string(mcontext.AuthTokenKey), "test-token")
				return next(c)
			}
		})
		e.Use(PathMiddleware(basePath, NewJWTLocModifier("auth")))
		e.POST("/files", testHandler)

		req := httptest.NewRequest(http.MethodPost, "/files", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "/12345?auth=test-token", rec.Header().Get("Location"))
	})
}

func mockTUSHandler(c echo.Context) error {
	switch c.Request().Method {
	case http.MethodPost:
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		c.Response().Header().Set("Location", "/files/123")
		return c.String(http.StatusCreated, "TUS post response")
	case http.MethodOptions:
		c.Response().Header().Set("Tus-Version", "1.0.0")
		c.Response().Header().Set("Tus-Resumable", "1.0.0")
		c.Response().Header().Set("Tus-Extension", "creation,termination")
		return c.String(http.StatusOK, "TUS options response")
	default:
		return c.String(http.StatusOK, "TUS response")
	}
}

func createTestToken(t *testing.T, ctx core.Context, subject string, purpose jwt.Purpose, expiresIn ...time.Duration) string {
	config := adapter.NewFromCore(ctx)
	expiry := time.Hour
	if len(expiresIn) > 0 {
		expiry = expiresIn[0]
	}

	token, err := jwt.CreateToken(
		config.GetPrivateKey(),
		config.GetDomain(),
		subject,
		purpose,
		expiry,
	)
	require.NoError(t, err)
	return token
}

type tusTestSetup struct {
	echoRouter *echo.Echo
	gRouter    router.Router
	accessSvc  *coreMocks.MockAccessService
	userSvc    *coreMocks.MockUserService
	ctx        core.Context
	basePath   string
}

func setupTusTest(t *testing.T) *tusTestSetup {
	t.Helper()

	echoRouter := echo.New()
	gRouter, err := router.NewSwaggerRouter(echoRouter, router.APIInfo().
		Title("TUS API").
		Version("1.0.0"))
	require.NoError(t, err)

	accessSvc := coreMocks.NewMockAccessService(t)
	userSvc := coreMocks.NewMockUserService(t)
	ctx := coreTesting.NewTestContext(t)
	ctx.RegisterService(core.USER_SERVICE, userSvc)

	// Common expectations
	accessSvc.EXPECT().CheckAccess(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	userSvc.On("IsAccountVerified", mock.Anything).Return(true, nil).Maybe()

	seedPhrase := wallet.NewSeedPhrase()

	cfg := ctx.Config()
	err = cfg.Update("core.domain", "main.example.com")
	if err != nil {
		t.Error(err)
	}
	err = cfg.Update("core.identity", seedPhrase)
	if err != nil {
		t.Error(err)
	}

	// Expected route registrations
	routeExpectations := []struct {
		subdomain string
		path      string
		method    string
		role      string
	}{
		{"test", "/files", "POST", "user"},
		{"test", "/files/:id", "HEAD", "user"},
		{"test", "/files/:id", "PATCH", "user"},
		{"test", "/files/:id", "DELETE", "user"},
		{"test", "/files", "OPTIONS", "user"},
	}

	for _, exp := range routeExpectations {
		accessSvc.EXPECT().
			RegisterRoute(exp.subdomain, exp.path, exp.method, exp.role).
			Return(nil).
			Once()
	}

	return &tusTestSetup{
		echoRouter: echoRouter,
		gRouter:    gRouter,
		accessSvc:  accessSvc,
		userSvc:    userSvc,
		ctx:        ctx,
		basePath:   "/files",
	}
}

func TestRegisterTusRoutes(t *testing.T) {
	t.Run("registers all TUS methods", func(t *testing.T) {
		setup := setupTusTest(t)

		err := RegisterTusRoutes(setup.ctx, setup.gRouter, setup.accessSvc, "test", setup.basePath, mockTUSHandler, false, false)
		assert.NoError(t, err)

		testCases := []struct {
			name           string
			method         string
			path           string
			expectedStatus int
		}{
			{"POST", http.MethodPost, setup.basePath, http.StatusCreated},
			{"HEAD", http.MethodHead, setup.basePath + "/123", http.StatusOK},
			{"PATCH", http.MethodPatch, setup.basePath + "/123", http.StatusOK},
			{"DELETE", http.MethodDelete, setup.basePath + "/123", http.StatusOK},
			{"OPTIONS", http.MethodOptions, setup.basePath, http.StatusNoContent},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				rr := httptest.NewRecorder()
				setup.echoRouter.ServeHTTP(rr, req)
				assert.Equal(t, tc.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("requires authentication when enabled", func(t *testing.T) {
		setup := setupTusTest(t)

		err := RegisterTusRoutes(setup.ctx, setup.gRouter, setup.accessSvc, "test", setup.basePath, mockTUSHandler, true, false)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, setup.basePath, nil)
		rr := httptest.NewRecorder()
		setup.echoRouter.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("allows access with valid token when auth enabled", func(t *testing.T) {
		setup := setupTusTest(t)

		err := RegisterTusRoutes(setup.ctx, setup.gRouter, setup.accessSvc, "test", setup.basePath, mockTUSHandler, true, false)
		assert.NoError(t, err)

		token := createTestToken(t, setup.ctx, "123", jwt.Purpose("login"))
		req := httptest.NewRequest(http.MethodPost, setup.basePath, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		setup.echoRouter.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)
	})

	t.Run("applies CORS headers", func(t *testing.T) {
		setup := setupTusTest(t)

		err := RegisterTusRoutes(setup.ctx, setup.gRouter, setup.accessSvc, "test", setup.basePath, mockTUSHandler, false, false)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodOptions, setup.basePath, nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "upload-offset")
		rr := httptest.NewRecorder()
		setup.echoRouter.ServeHTTP(rr, req)

		headers := rr.Header()
		assert.Equal(t, "http://example.com", headers.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "POST", headers.Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "true", headers.Get("Access-Control-Allow-Credentials"))
	})

}
