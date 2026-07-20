// Package api — relay catalog management.
//
// The relay catalog is the structured, server-side configuration that
// describes which relay servers exist, what their logical audience IDs are,
// and how clients should connect.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

// RelayDescriptor describes a single relay server.
type RelayDescriptor struct {
	Region   string `json:"region"`
	Audience string `json:"audience"`
	Endpoint string `json:"endpoint"`
}

// RelayCatalog is a collection of relay descriptors keyed by audience.
type RelayCatalog struct {
	mu      sync.RWMutex
	byAud   map[string]*RelayDescriptor // audience -> descriptor
	byReg   map[string]*RelayDescriptor // region -> descriptor
	entries []RelayDescriptor           // ordered list
}

// Validate checks that the descriptor is well-formed.
func (d *RelayDescriptor) Validate() error {
	if strings.TrimSpace(d.Region) == "" {
		return fmt.Errorf("relay descriptor region is required")
	}
	if strings.TrimSpace(d.Audience) == "" {
		return fmt.Errorf("relay descriptor audience is required")
	}
	if strings.TrimSpace(d.Endpoint) == "" {
		return fmt.Errorf("relay descriptor endpoint is required")
	}

	// Validate endpoint scheme
	ep := strings.TrimSpace(d.Endpoint)
	if strings.HasPrefix(ep, "tls://") {
		hostPort := strings.TrimPrefix(ep, "tls://")
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			return fmt.Errorf("relay descriptor endpoint %q: invalid host:port: %w", ep, err)
		}
	} else if strings.HasPrefix(ep, "tcp://") {
		hostPort := strings.TrimPrefix(ep, "tcp://")
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			return fmt.Errorf("relay descriptor endpoint %q: invalid host:port: %w", ep, err)
		}
	} else {
		// Legacy: bare host:port is treated as tcp:// for backward compat
		if _, _, err := net.SplitHostPort(ep); err != nil {
			return fmt.Errorf("relay descriptor endpoint %q: must use tls://host:port or tcp://host:port", ep)
		}
	}

	return nil
}

// NormalizeEndpoint ensures the endpoint has a scheme. Legacy bare host:port
// endpoints are prefixed with tcp:// for backward compatibility.
func (d *RelayDescriptor) NormalizeEndpoint() {
	ep := strings.TrimSpace(d.Endpoint)
	if !strings.HasPrefix(ep, "tls://") && !strings.HasPrefix(ep, "tcp://") {
		d.Endpoint = "tcp://" + ep
	}
}

// Scheme returns "tls" or "tcp".
func (d *RelayDescriptor) Scheme() string {
	if strings.HasPrefix(d.Endpoint, "tls://") {
		return "tls"
	}
	return "tcp"
}

// HostPort returns the host:port portion of the endpoint.
func (d *RelayDescriptor) HostPort() string {
	ep := d.Endpoint
	ep = strings.TrimPrefix(ep, "tls://")
	ep = strings.TrimPrefix(ep, "tcp://")
	return ep
}

// ParseRelayCatalogJSON parses a JSON array of relay descriptors.
// Example:
//
//	[
//	  {"region": "sg", "audience": "relay-sg-1", "endpoint": "tls://relay.example.com:18081"},
//	  {"region": "us", "audience": "relay-us-1", "endpoint": "tls://relay-us.example.com:18081"}
//	]
func ParseRelayCatalogJSON(raw string) (*RelayCatalog, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var entries []RelayDescriptor
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("RELAY_CATALOG_JSON: invalid JSON: %w", err)
	}

	catalog := &RelayCatalog{
		byAud: make(map[string]*RelayDescriptor),
		byReg: make(map[string]*RelayDescriptor),
	}

	for i := range entries {
		d := &entries[i]
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("RELAY_CATALOG_JSON: entry %d: %w", i, err)
		}
		d.NormalizeEndpoint()

		if _, exists := catalog.byAud[d.Audience]; exists {
			return nil, fmt.Errorf("RELAY_CATALOG_JSON: duplicate audience %q", d.Audience)
		}

		catalog.byAud[d.Audience] = d
		catalog.byReg[d.Region] = d
		catalog.entries = append(catalog.entries, *d)
	}

	return catalog, nil
}

// LookupByAudience returns the descriptor for an audience, or nil.
func (c *RelayCatalog) LookupByAudience(audience string) *RelayDescriptor {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byAud[audience]
}

// LookupByRegion returns the descriptor for a region, or nil.
func (c *RelayCatalog) LookupByRegion(region string) *RelayDescriptor {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byReg[region]
}

// Entries returns a copy of all relay descriptors.
func (c *RelayCatalog) Entries() []RelayDescriptor {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]RelayDescriptor, len(c.entries))
	copy(out, c.entries)
	return out
}

// AudienceExists checks if an audience is in the catalog.
func (c *RelayCatalog) AudienceExists(audience string) bool {
	return c.LookupByAudience(audience) != nil
}

// LoadRelayCatalog reads RELAY_CATALOG_JSON from the environment.
func LoadRelayCatalog() (*RelayCatalog, error) {
	raw := strings.TrimSpace(os.Getenv("RELAY_CATALOG_JSON"))
	if raw == "" {
		// Fall back to legacy RELAY_SERVERS for backward compatibility.
		// Legacy format does not support tls:// scheme and is treated as
		// development-only path.
		return legacyRelayServersCatalog()
	}
	return ParseRelayCatalogJSON(raw)
}

// legacyRelayServersCatalog builds a minimal catalog from the legacy
// RELAY_SERVERS env var. Each entry gets a synthetic audience/region.
// This path exists only for backward compatibility; production deployments
// should use RELAY_CATALOG_JSON with explicit tls:// endpoints.
func legacyRelayServersCatalog() (*RelayCatalog, error) {
	raw := strings.TrimSpace(os.Getenv("RELAY_SERVERS"))
	if raw == "" {
		return nil, nil
	}

	entries := []RelayDescriptor{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse region@endpoint or bare endpoint
		region := "default"
		endpoint := part
		if idx := strings.Index(part, "@"); idx > 0 {
			region = strings.TrimSpace(part[:idx])
			endpoint = strings.TrimSpace(part[idx+1:])
		}

		// Legacy endpoints are assumed to be tcp:// for backward compat
		audience := fmt.Sprintf("relay-%s", region)

		d := RelayDescriptor{
			Region:   region,
			Audience: audience,
			Endpoint: endpoint,
		}
		d.NormalizeEndpoint()
		entries = append(entries, d)
	}

	// Build catalog from synthetic entries
	catalog := &RelayCatalog{
		byAud: make(map[string]*RelayDescriptor),
		byReg: make(map[string]*RelayDescriptor),
	}

	for i := range entries {
		d := &entries[i]
		// Allow duplicate audience/region for legacy (different entries may parse to same region)
		if _, exists := catalog.byAud[d.Audience]; !exists {
			catalog.byAud[d.Audience] = d
		}
		if _, exists := catalog.byReg[d.Region]; !exists {
			catalog.byReg[d.Region] = d
		}
		catalog.entries = append(catalog.entries, *d)
	}

	return catalog, nil
}

// urlParse is a thin wrapper for tests.
var urlParse = url.Parse

func init() {
	_ = urlParse // suppress unused warning
}
