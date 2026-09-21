package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/database"
)

const minAdminTokenLength = 32

//go:embed web/*
var embeddedWeb embed.FS

type Store interface {
	AdminOverviewSnapshot() (*database.AdminOverview, error)
	AdminAccounts(query string, limit, offset int) (*database.AdminAccountPage, error)
	AdminAccountsCursor(query, afterID string, limit int) (*database.AdminAccountCursorPage, error)
	AdminAccount(accountID string) (*database.AdminAccountDetail, error)
	AdminTopology(accountID string) (*database.AdminTopology, error)
	AdminTopologyPage(afterAccountID string, accountLimit, nodeBudget int) (*database.AdminTopologyPage, error)
	AdminDevices(query, status string, limit, offset int) (*database.AdminDevicePage, error)
	AdminNetworks(limit, offset int) (*database.AdminNetworkPage, error)
	AdminRooms(limit, offset int) (*database.AdminRoomPage, error)
	AdminConnections(filter database.AdminConnectionFilter, limit, offset int) (*database.AdminConnectionPage, error)
	AdminConnectionTransitions(filter database.AdminConnectionTransitionFilter, limit int, cursor string) (*database.AdminConnectionTransitionPage, error)
	AdminConnectionHealth(filter database.AdminConnectionHealthFilter) (*database.AdminConnectionHealth, error)
	AdminConnectionTrends(filter database.AdminConnectionTrendsFilter) (*database.AdminConnectionTrends, error)
}

type Config struct {
	Token        string
	BuildVersion string
	BuildCommit  string
	StartedAt    time.Time
}

type Server struct {
	store        Store
	tokenHash    [sha256.Size]byte
	enabled      bool
	buildVersion string
	buildCommit  string
	startedAt    time.Time
	files        http.Handler
}

func New(store Store, config Config) (*Server, error) {
	token := strings.TrimSpace(config.Token)
	if token != "" && len(token) < minAdminTokenLength {
		return nil, fmt.Errorf("CONTROL_ADMIN_TOKEN must be empty or at least %d characters", minAdminTokenLength)
	}
	if token != "" && store == nil {
		return nil, errors.New("admin store is required when the console is enabled")
	}
	webRoot, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		return nil, fmt.Errorf("prepare embedded admin console: %w", err)
	}
	startedAt := config.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	return &Server{
		store:        store,
		tokenHash:    sha256.Sum256([]byte(token)),
		enabled:      token != "",
		buildVersion: strings.TrimSpace(config.BuildVersion),
		buildCommit:  strings.TrimSpace(config.BuildCommit),
		startedAt:    startedAt,
		files:        http.FileServer(http.FS(webRoot)),
	}, nil
}

func (s *Server) Enabled() bool {
	return s.enabled
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	if !s.enabled {
		// Without a token the console does not exist, and the documented
		// contract is that /admin and /admin/* answer 404. Register the paths
		// without a method so every verb still answers 404: method-specific
		// patterns would answer 405 instead, which would confirm to an
		// unauthenticated caller that the admin surface is registered.
		mux.HandleFunc("/admin", http.NotFound)
		mux.HandleFunc("/admin/", http.NotFound)
		return
	}
	mux.HandleFunc("GET /admin", s.redirectConsole)
	mux.HandleFunc("GET /admin/api/v1/overview", s.requireAdmin(s.overview))
	mux.HandleFunc("GET /admin/api/v1/accounts", s.requireAdmin(s.accounts))
	mux.HandleFunc("GET /admin/api/v1/accounts/cursor", s.requireAdmin(s.accountsCursor))
	mux.HandleFunc("GET /admin/api/v1/accounts/{id}/topology", s.requireAdmin(s.accountTopology))
	mux.HandleFunc("GET /admin/api/v1/accounts/{id}", s.requireAdmin(s.account))
	mux.HandleFunc("GET /admin/api/v1/topology", s.requireAdmin(s.topology))
	mux.HandleFunc("GET /admin/api/v1/devices", s.requireAdmin(s.devices))
	mux.HandleFunc("GET /admin/api/v1/networks", s.requireAdmin(s.networks))
	mux.HandleFunc("GET /admin/api/v1/rooms", s.requireAdmin(s.rooms))
	mux.HandleFunc("GET /admin/api/v1/connections", s.requireAdmin(s.connections))
	mux.HandleFunc("GET /admin/api/v1/connection-transitions", s.requireAdmin(s.connectionTransitions))
	mux.HandleFunc("GET /admin/api/v1/connection-health", s.requireAdmin(s.connectionHealth))
	mux.HandleFunc("GET /admin/api/v1/connection-trends", s.requireAdmin(s.connectionTrends))
	mux.HandleFunc("GET /admin/api/v1/runtime", s.requireAdmin(s.runtime))
	mux.HandleFunc("GET /admin/", s.serveConsole)
}

func (s *Server) redirectConsole(w http.ResponseWriter, r *http.Request) {
	setBrowserSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	if !s.enabled {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
}

func (s *Server) serveConsole(w http.ResponseWriter, r *http.Request) {
	if !s.enabled {
		http.NotFound(w, r)
		return
	}
	setBrowserSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")

	asset := strings.TrimPrefix(r.URL.Path, "/admin/")
	switch asset {
	case "", "index.html":
		asset = "index.html"
	case "app.css", "app.js":
		// Static build artifacts are served as-is.
	default:
		// BrowserRouter uses clean paths such as /admin/accounts/:id. Any path
		// without a file extension is an SPA route and must receive index.html so
		// refresh/deep-link navigation works. Unknown asset-looking paths remain
		// 404 instead of accidentally serving HTML as JavaScript or CSS.
		if strings.Contains(asset, ".") {
			http.NotFound(w, r)
			return
		}
		asset = "index.html"
	}

	clone := r.Clone(r.Context())
	if asset == "index.html" {
		clone.URL.Path = "/"
	} else {
		clone.URL.Path = "/" + asset
	}
	clone.URL.RawPath = ""
	s.files.ServeHTTP(w, clone)
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setBrowserSecurityHeaders(w)
		w.Header().Set("Cache-Control", "no-store")
		if !s.enabled {
			http.NotFound(w, r)
			return
		}
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			s.writeUnauthorized(w)
			return
		}
		candidateHash := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))))
		if subtle.ConstantTimeCompare(candidateHash[:], s.tokenHash[:]) != 1 {
			s.writeUnauthorized(w)
			return
		}
		next(w, r)
	}
}

func (s *Server) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="p2wlan-admin"`)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin authentication required"})
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	value, err := s.store.AdminOverviewSnapshot()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load admin overview"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminAccounts(r.URL.Query().Get("q"), limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load accounts"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) accountsCursor(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInt(r.URL.Query().Get("limit"), 25, 1, 200)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
		return
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if len(cursor) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cursor is too long"})
		return
	}
	value, err := s.store.AdminAccountsCursor(r.URL.Query().Get("q"), cursor, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load accounts"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	value, err := s.store.AdminAccount(r.PathValue("id"))
	if errors.Is(err, database.ErrAdminAccountNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load account"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	accountLimit, err := parseBoundedInt(r.URL.Query().Get("limit"), 12, 1, 50)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 50"})
		return
	}
	nodeBudget, err := parseBoundedInt(r.URL.Query().Get("node_limit"), 600, 1, 2000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_limit must be between 1 and 2000"})
		return
	}
	if nodeBudget < accountLimit {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_limit must be greater than or equal to limit"})
		return
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if len(cursor) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cursor is too long"})
		return
	}
	value, err := s.store.AdminTopologyPage(cursor, accountLimit, nodeBudget)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load topology"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) accountTopology(w http.ResponseWriter, r *http.Request) {
	value, err := s.store.AdminTopology(r.PathValue("id"))
	if errors.Is(err, database.ErrAdminAccountNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load account topology"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminDevices(r.URL.Query().Get("q"), r.URL.Query().Get("status"), limit, offset)
	if err != nil {
		if errors.Is(err, database.ErrInvalidAdminDeviceStatus) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status filter"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load devices"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminNetworks(limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load networks"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) rooms(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminRooms(limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load rooms"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) runtime(w http.ResponseWriter, _ *http.Request) {
	uptime := time.Since(s.startedAt)
	if uptime < 0 {
		uptime = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"build_version":  emptyFallback(s.buildVersion, "dev"),
		"build_commit":   emptyFallback(s.buildCommit, "unknown"),
		"started_at":     s.startedAt.Unix(),
		"uptime_seconds": int64(uptime / time.Second),
		"admin_mode":     "read-only",
	})
}

func parseBoundedInt(raw string, fallback, minValue, maxValue int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minValue || value > maxValue {
		return 0, errors.New("value outside allowed range")
	}
	return value, nil
}

func parsePage(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	parse := func(name string, fallback int) (int, error) {
		raw := strings.TrimSpace(r.URL.Query().Get(name))
		if raw == "" {
			return fallback, nil
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", name)
		}
		return value, nil
	}
	limit, err := parse("limit", 50)
	if err != nil || limit < 1 || limit > 200 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
		return 0, 0, false
	}
	offset, err := parse("offset", 0)
	if err != nil || offset < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "offset must be zero or greater"})
		return 0, 0, false
	}
	return limit, offset, true
}

func setBrowserSecurityHeaders(w http.ResponseWriter) {
	// React Flow positions nodes and account identity colors with style
	// attributes. Keep script execution strictly same-origin while permitting
	// style attributes only; inline scripts and inline <style> blocks remain
	// disallowed by the policy.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
