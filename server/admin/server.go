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
	AdminDevices(query, status string, limit, offset int) (*database.AdminDevicePage, error)
	AdminNetworks(limit, offset int) (*database.AdminNetworkPage, error)
	AdminRooms(limit, offset int) (*database.AdminRoomPage, error)
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
	mux.HandleFunc("GET /admin", s.redirectConsole)
	mux.HandleFunc("GET /admin/api/v1/overview", s.requireAdmin(s.overview))
	mux.HandleFunc("GET /admin/api/v1/devices", s.requireAdmin(s.devices))
	mux.HandleFunc("GET /admin/api/v1/networks", s.requireAdmin(s.networks))
	mux.HandleFunc("GET /admin/api/v1/rooms", s.requireAdmin(s.rooms))
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
	if asset == "" {
		asset = "index.html"
	}
	switch asset {
	case "index.html", "app.css", "app.js":
	default:
		http.NotFound(w, r)
		return
	}
	clone := r.Clone(r.Context())
	if asset == "index.html" {
		// FileServer redirects an explicit /index.html to ./; serving the embedded
		// root here avoids turning /admin/ into a redirect loop.
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
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
