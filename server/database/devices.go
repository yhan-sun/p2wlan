package database

import (
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var natGenRegex = regexp.MustCompile(`\bg=(\d+)\b`)

func parseNATGeneration(natType string) (int64, bool) {
	matches := natGenRegex.FindStringSubmatch(natType)
	if len(matches) < 2 {
		return 0, false
	}
	gen, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return gen, true
}

type parsedNAT struct {
	raw          string
	hasGen       bool
	generation   int64
	mapping      string
	filtering    string
	allocation   string
	hasRev       bool
	revision     int64
	hasObs       bool
	observation  int64
	hasLifecycle bool
	lifecycle    string
}

func parseNAT(natType string) parsedNAT {
	p := parsedNAT{raw: strings.TrimSpace(natType)}
	if p.raw == "" || strings.EqualFold(p.raw, "unknown") {
		return p
	}
	payload := p.raw
	if strings.HasPrefix(payload, "p2v2:") {
		payload = strings.TrimPrefix(payload, "p2v2:")
	} else if strings.HasPrefix(payload, "p2:") {
		payload = strings.TrimPrefix(payload, "p2:")
	}
	tokens := strings.Split(payload, ";")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "g":
			if g, err := strconv.ParseInt(v, 10, 64); err == nil {
				p.hasGen = true
				p.generation = g
			}
		case "m":
			p.mapping = strings.ToLower(v)
		case "f":
			p.filtering = strings.ToLower(v)
		case "a":
			p.allocation = strings.ToLower(v)
		case "r":
			if r, err := strconv.ParseInt(v, 10, 64); err == nil {
				p.hasRev = true
				p.revision = r
			}
		case "o":
			if o, err := strconv.ParseInt(v, 10, 64); err == nil {
				p.hasObs = true
				p.observation = o
			}
		case "l":
			p.hasLifecycle = true
			p.lifecycle = v
		}
	}
	return p
}

func shouldOverwriteNAT(currentEndpoint, currentNAT string, currentRegSeq int64, requireLifecycle bool, incomingEndpoint, incomingNAT string) bool {
	curr := parseNAT(currentNAT)
	inc := parseNAT(incomingNAT)

	// An incarnation-aware registration has a server-issued sequence. Every
	// endpoint update for it must echo that exact lifecycle. Merely rejecting a
	// lower `l=` is insufficient: an old/legacy request can omit `l=`, and a
	// malformed or guessed higher value must not clobber the newer process's
	// endpoint facts. Legacy rows retain the historical optional-label behavior
	// for a rolling upgrade.
	if requireLifecycle {
		if !inc.hasLifecycle {
			return false
		}
		reqSeq, err := strconv.ParseInt(inc.lifecycle, 10, 64)
		if err != nil || reqSeq != currentRegSeq {
			return false
		}
	} else if inc.hasLifecycle {
		// Preserve old-client compatibility while still refusing a clearly stale
		// lifecycle label on a legacy device.
		if reqSeq, err := strconv.ParseInt(inc.lifecycle, 10, 64); err == nil && reqSeq < currentRegSeq {
			return false
		}
	}

	if curr.hasGen {
		// Versioned metadata cannot be replaced by unversioned/unknown
		if !inc.hasGen {
			return false
		}
		// Lower generation is stale
		if inc.generation < curr.generation {
			return false
		}
		// Same generation checks
		if inc.generation == curr.generation {
			// Capability conflicts: mapping, filtering, allocation
			if curr.mapping != "" && inc.mapping != "" && curr.mapping != inc.mapping {
				return false
			}
			if curr.filtering != "" && inc.filtering != "" && curr.filtering != inc.filtering {
				return false
			}
			if curr.allocation != "" && inc.allocation != "" && curr.allocation != inc.allocation {
				return false
			}
			// Empty incoming endpoint cannot wipe out a valid non-empty current endpoint
			if strings.TrimSpace(incomingEndpoint) == "" && strings.TrimSpace(currentEndpoint) != "" {
				return false
			}
			// Stale capability revision
			if inc.hasRev && curr.hasRev && inc.revision < curr.revision {
				return false
			}
			// Stale observation sequence
			if inc.hasObs && curr.hasObs && inc.observation < curr.observation {
				return false
			}
			return true
		}
		// Higher generation: allowed
		return true
	}

	// Current NAT is unversioned/unknown: incoming is accepted
	return true
}

// GetDevice retrieves a device by ID.
func (db *DB) GetDevice(deviceID string) (*Device, error) {
	var d Device
	var online int
	var relayRTTMS sql.NullInt64
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(ed25519_public_key, ''), COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0)
		FROM devices WHERE id = ?`, deviceID).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt, &d.Ed25519PublicKey, &d.RegistrationSeq, &d.RegistrationIncarnation)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
	return &d, nil
}

// ---- Device operations ----

// Device represents a registered device/node.
type Device struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	NetworkID        string `json:"network_id"`
	PublicKey        string `json:"public_key"`
	DeviceName       string `json:"device_name"`
	Platform         string `json:"platform"`
	VirtualIP        string `json:"virtual_ip"`
	NATType          string `json:"nat_type"`
	Endpoint         string `json:"endpoint"`
	RelayRTTMS       *int64 `json:"relay_rtt_ms,omitempty"`
	LastSeen         int64  `json:"last_seen"`
	AppVersion       string `json:"app_version"`
	Online           bool   `json:"online"`
	Ed25519PublicKey string `json:"ed25519_public_key,omitempty"`
	// RegistrationSeq identifies the current daemon/transport incarnation. It
	// is intentionally independent from device credentials: a restart must not
	// invalidate the bearer token that authorized that restart.
	RegistrationSeq int64 `json:"registration_seq,omitempty"`
	// RegistrationIncarnation is the daemon's persisted, monotonic boot
	// incarnation. It is kept private because it is a control-plane fencing
	// value rather than peer-visible metadata.
	RegistrationIncarnation int64 `json:"-"`
	CreatedAt               int64 `json:"created_at"`
}

// DeviceRegistrationAttempt provides the monotonic boot-incarnation proof
// sent by current daemon builds. The daemon reserves this value in durable
// local state before it contacts the control plane, so a duplicate request
// from the same boot is idempotent while a late request from an older boot is
// fenced without revoking its long-lived device credential.
//
// EnforceIncarnation is set only on untrusted HTTP registration requests. The
// older CreateDeviceWithOptions API remains available to trusted internal
// callers and migration tests without changing its historical signature.
type DeviceRegistrationAttempt struct {
	Incarnation        *int64
	EnforceIncarnation bool
}

// RegistrationConflictError is returned when an in-flight registration no
// longer matches the server's current transport incarnation. Clients must not
// retry it with a newer incarnation because that could let an old daemon replace
// a newer daemon's endpoint state.
type RegistrationConflictError struct {
	CurrentSequence    int64
	CurrentIncarnation int64
	Code               string
}

func (e *RegistrationConflictError) Error() string {
	if e.Code == "registration_protocol_upgrade_required" {
		return "registration requires a sequence-aware client"
	}
	return "registration sequence conflict"
}

// RegistrationSessionConflictError means an authenticated device credential
// presented a registration sequence that is no longer current.  It is
// separate from RegistrationConflictError: the latter fences a registration
// request by its durable boot incarnation, while this error fences a normal
// control action from an already superseded daemon process.
type RegistrationSessionConflictError struct {
	CurrentSequence    int64
	CurrentIncarnation int64
}

func (e *RegistrationSessionConflictError) Error() string {
	return "registration lifecycle conflict"
}

func validateDeviceRegistrationAttempt(attempt DeviceRegistrationAttempt) error {
	if !attempt.EnforceIncarnation {
		return nil
	}
	if attempt.Incarnation != nil && *attempt.Incarnation < 0 {
		return fmt.Errorf("registration_incarnation must not be negative")
	}
	return nil
}

func nullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

// CreateDevice inserts a new device and assigns a virtual IP.
func (db *DB) CreateDevice(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey string) (*Device, error) {
	return db.CreateDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, "", "")
}

// CreateDeviceWithOptions inserts or updates a device with optional runtime metadata.
func (db *DB) CreateDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion string) (*Device, error) {
	return db.registerDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion, DeviceRegistrationAttempt{})
}

// RegisterDeviceWithOptions performs a sequence-aware daemon registration.
// HTTP callers must set EnforceIncarnation; this prevents a late request from a
// previous daemon process from clearing the endpoint facts published by a
// newer process that holds the same long-lived device credential.
func (db *DB) RegisterDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion string, attempt DeviceRegistrationAttempt) (*Device, error) {
	return db.registerDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion, attempt)
}

func (db *DB) registerDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion string, attempt DeviceRegistrationAttempt) (*Device, error) {
	if err := validateDeviceRegistrationAttempt(attempt); err != nil {
		return nil, err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var room, member bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM rooms WHERE network_id = ?), EXISTS(SELECT 1 FROM network_memberships WHERE network_id = ? AND user_id = ?)`, networkID, networkID, userID).Scan(&room, &member); err != nil {
		return nil, err
	}
	if room && !member {
		return nil, ErrRoomAccess
	}
	if room && strings.TrimSpace(requestedVirtualIP) != "" {
		return nil, ErrRoomInvalid
	}

	if room {
		access, err := ensureRoomDeviceAccess(tx, userID, networkID, publicKey, deviceName, platform)
		if err != nil {
			return nil, err
		}
		if denied := roomDeviceStateError(access.State); denied != nil {
			if err = tx.Commit(); err != nil {
				return nil, err
			}
			return nil, denied
		}
	}

	var existing Device
	var online int
	var existingRelayRTTMS sql.NullInt64
	err = tx.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0)
		FROM devices WHERE public_key = ? LIMIT 1`, publicKey).
		Scan(&existing.ID, &existing.UserID, &existing.NetworkID, &existing.PublicKey, &existing.DeviceName, &existing.Platform,
			&existing.VirtualIP, &existing.NATType, &existing.Endpoint, &existingRelayRTTMS, &existing.LastSeen, &existing.AppVersion, &online, &existing.CreatedAt, &existing.RegistrationSeq, &existing.RegistrationIncarnation)
	if err == nil {
		if existing.UserID != userID {
			return nil, fmt.Errorf("public key is already registered by another user")
		}
		if existing.NetworkID != networkID {
			return nil, fmt.Errorf("public key is already registered in another network")
		}
		if attempt.EnforceIncarnation {
			if attempt.Incarnation == nil || *attempt.Incarnation == 0 {
				// A legacy client may perform one migration registration while
				// this field is still empty. Once an incarnation-aware daemon has
				// registered, allowing a request with no fencing proof would let an
				// old in-flight request overwrite that newer incarnation.
				if existing.RegistrationIncarnation != 0 {
					return nil, &RegistrationConflictError{
						CurrentSequence:    existing.RegistrationSeq,
						CurrentIncarnation: existing.RegistrationIncarnation,
						Code:               "registration_protocol_upgrade_required",
					}
				}
			} else {
				incoming := *attempt.Incarnation
				if incoming == existing.RegistrationIncarnation {
					// Idempotent retry after a lost response. Preserve endpoint/NAT
					// facts that this same boot may already have published, but refresh
					// its online lease.
					now := time.Now().Unix()
					if _, err := tx.Exec(`UPDATE devices SET last_seen = ?, online = 1 WHERE id = ?`, now, existing.ID); err != nil {
						return nil, err
					}
					if err := tx.Commit(); err != nil {
						return nil, err
					}
					existing.LastSeen = now
					existing.Online = true
					return &existing, nil
				}
				if incoming < existing.RegistrationIncarnation {
					return nil, &RegistrationConflictError{
						CurrentSequence:    existing.RegistrationSeq,
						CurrentIncarnation: existing.RegistrationIncarnation,
						Code:               "registration_conflict",
					}
				}
			}
		}

		virtualIP := existing.VirtualIP
		if strings.TrimSpace(requestedVirtualIP) != "" && requestedVirtualIP != existing.VirtualIP {
			virtualIP, err = db.reserveVirtualIP(tx, networkID, requestedVirtualIP, existing.ID)
			if err != nil {
				return nil, err
			}
		}

		now := time.Now().Unix()
		// A registration is a new daemon incarnation, while endpoint/NAT/relay
		// RTT describe the previous process's runtime transport. Clear all three
		// atomically before publishing online=1; the first authenticated endpoint
		// PATCH will publish facts for the new incarnation.
		registrationIncarnation := existing.RegistrationIncarnation
		if attempt.EnforceIncarnation && attempt.Incarnation != nil && *attempt.Incarnation > 0 {
			registrationIncarnation = *attempt.Incarnation
		}
		_, err = tx.Exec(`UPDATE devices SET device_name = ?, platform = ?, virtual_ip = ?, app_version = CASE WHEN ? != '' THEN ? ELSE app_version END, endpoint = '', nat_type = 'unknown', relay_rtt_ms = NULL, last_seen = ?, online = 1, ed25519_public_key = CASE WHEN ? != '' THEN ? ELSE ed25519_public_key END, registration_seq = COALESCE(registration_seq, 1) + 1, registration_incarnation = ? WHERE id = ?`,
			deviceName, platform, virtualIP, appVersion, appVersion, now, ed25519PublicKey, ed25519PublicKey, registrationIncarnation, existing.ID)
		if err != nil {
			return nil, err
		}
		// Registration changes the daemon's transport incarnation. It does not
		// change the device identity that authenticated this request. In
		// particular, revoking credentials here would allow a device-token-only
		// daemon to receive HTTP 200 and then lose the sole token needed for its
		// next heartbeat if the response is dropped. Credential invalidation is
		// deliberately limited to explicit credential revocation, device deletion,
		// and room-access revocation. The registration sequence is returned to
		// the daemon so endpoint metadata can distinguish transport incarnations
		// without treating a restart as a credential-revocation event.
		if err := tx.Commit(); err != nil {
			return nil, err
		}

		existing.DeviceName = deviceName
		existing.Platform = platform
		existing.VirtualIP = virtualIP
		existing.Endpoint = ""
		existing.NATType = "unknown"
		existing.RelayRTTMS = nil
		if appVersion != "" {
			existing.AppVersion = appVersion
		}
		existing.LastSeen = now
		existing.Online = true
		existing.RegistrationSeq++
		existing.RegistrationIncarnation = registrationIncarnation
		return &existing, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}

	idSuffix := publicKey
	if len(idSuffix) > 16 {
		idSuffix = idSuffix[:16]
	}
	id, err := roomRandomID("node-"+idSuffix+"-", 16)
	if err != nil {
		return nil, fmt.Errorf("generate device ID: %w", err)
	}
	now := time.Now().Unix()

	virtualIP, err := db.reserveVirtualIP(tx, networkID, requestedVirtualIP, "")
	if err != nil {
		return nil, err
	}

	registrationIncarnation := int64(0)
	if attempt.EnforceIncarnation && attempt.Incarnation != nil && *attempt.Incarnation > 0 {
		registrationIncarnation = *attempt.Incarnation
	}
	_, err = tx.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, app_version, last_seen, online, created_at, ed25519_public_key, registration_seq, registration_incarnation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?)`,
		id, userID, networkID, publicKey, deviceName, platform, virtualIP, appVersion, now, now, ed25519PublicKey, registrationIncarnation)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Device{
		ID: id, UserID: userID, NetworkID: networkID,
		PublicKey: publicKey, DeviceName: deviceName, Platform: platform,
		VirtualIP: virtualIP, AppVersion: appVersion, LastSeen: now, Online: true,
		Ed25519PublicKey: ed25519PublicKey, RegistrationSeq: 1, RegistrationIncarnation: registrationIncarnation, CreatedAt: now,
	}, nil
}

// GetDeviceByPublicKey looks up a device by network and public key.
func (db *DB) GetDeviceByPublicKey(networkID, publicKey string) (*Device, error) {
	var d Device
	var online int
	var relayRTTMS sql.NullInt64
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(ed25519_public_key, ''), COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0)
		FROM devices WHERE network_id = ? AND public_key = ? LIMIT 1`, networkID, publicKey).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt, &d.Ed25519PublicKey, &d.RegistrationSeq, &d.RegistrationIncarnation)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
	return &d, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

func networkIP(ipnet *net.IPNet) net.IP {
	base := ipnet.IP.To4()
	if base == nil {
		base = ipnet.IP
	}
	network := make(net.IP, len(base))
	copy(network, base)
	return network
}

func broadcastIP(ipnet *net.IPNet) net.IP {
	base := networkIP(ipnet)
	broadcast := make(net.IP, len(base))
	for i := range broadcast {
		broadcast[i] = base[i] | ^ipnet.Mask[i]
	}
	return broadcast
}

// reserveVirtualIP validates a requested IP or finds the next available IP in a network.
func (db *DB) reserveVirtualIP(tx *sql.Tx, networkID, requestedIP, excludeDeviceID string) (string, error) {
	var cidr string
	err := tx.QueryRow(`SELECT cidr FROM networks WHERE id = ?`, networkID).Scan(&cidr)
	if err != nil {
		return "", fmt.Errorf("query network cidr: %w", err)
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse network cidr '%s': %w", cidr, err)
	}

	network := networkIP(ipnet)
	broadcast := broadcastIP(ipnet)
	requestedIP = strings.TrimSpace(requestedIP)
	if requestedIP != "" {
		ip := net.ParseIP(requestedIP).To4()
		if ip == nil {
			return "", fmt.Errorf("virtual_ip must be an IPv4 address")
		}
		if !ipnet.Contains(ip) {
			return "", fmt.Errorf("virtual_ip %s is outside network CIDR %s", ip.String(), cidr)
		}
		if ip.Equal(network) || ip.Equal(broadcast) {
			return "", fmt.Errorf("virtual_ip %s cannot be the network or broadcast address", ip.String())
		}
		var existingID string
		err := tx.QueryRow(`SELECT id FROM devices WHERE network_id = ? AND virtual_ip = ? LIMIT 1`, networkID, ip.String()).Scan(&existingID)
		if err == nil && existingID != excludeDeviceID {
			return "", fmt.Errorf("virtual_ip %s is already assigned", ip.String())
		}
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}
		return ip.String(), nil
	}

	rows, err := tx.Query(`SELECT virtual_ip FROM devices WHERE network_id = ?`, networkID)
	if err != nil {
		return "", fmt.Errorf("query allocated IPs: %w", err)
	}
	defer rows.Close()

	allocated := make(map[string]bool)
	for rows.Next() {
		var vip string
		if err := rows.Scan(&vip); err != nil {
			return "", err
		}
		allocated[vip] = true
	}

	curr := nextIP(network) // Network address (skip)
	curr = nextIP(curr)     // Start from .2
	for ipnet.Contains(curr) {
		if curr.Equal(broadcast) {
			break
		}
		ipStr := curr.String()
		if !allocated[ipStr] {
			return ipStr, nil
		}
		curr = nextIP(curr)
	}

	return "", fmt.Errorf("IP address pool exhausted for network %s", networkID)
}

// assignVirtualIP finds the next available virtual IP in a network.
func (db *DB) assignVirtualIP(tx *sql.Tx, networkID string) (string, error) {
	return db.reserveVirtualIP(tx, networkID, "", "")
}

// DeviceOnlineTTL is how long a device remains "online" without a last_seen update.
// The daemon's default control heartbeat is 5 seconds, so three missed
// heartbeats converge an abnormal exit to offline without flapping on one
// delayed request.
const DeviceOnlineTTL = 15

// ListDevicesByNetwork returns all devices in a network.
// Devices whose last_seen is older than DeviceOnlineTTL are reported as offline
// even if the online flag is still set (lease / TTL semantics).
func (db *DB) ListDevicesByNetwork(networkID string) ([]Device, error) {
	return db.listDevices(`FROM devices WHERE network_id = ?`, networkID)
}

// ListDevicesByUserAndNetwork returns only the devices owned by userID in the
// requested network. Network membership is not ownership: the control-plane
// user API must not expose another account's device roster just because both
// accounts are members of the legacy shared default network.
func (db *DB) ListDevicesByUserAndNetwork(userID, networkID string) ([]Device, error) {
	return db.listDevices(`FROM devices WHERE user_id = ? AND network_id = ?`, userID, networkID)
}

func (db *DB) listDevices(fromClause string, args ...interface{}) ([]Device, error) {
	now := time.Now().Unix()

	rows, err := db.Query(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0) `+fromClause, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var online int
		var relayRTTMS sql.NullInt64
		if err := rows.Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt, &d.RegistrationSeq, &d.RegistrationIncarnation); err != nil {
			return nil, err
		}
		d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
		// Lease semantics: last_seen older than TTL or never seen (0) => offline.
		if online == 1 && d.LastSeen > 0 && now-d.LastSeen <= DeviceOnlineTTL {
			d.Online = true
		} else {
			d.Online = false
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// MarkStaleDevicesOffline sets online=0 for devices whose last_seen is older than ttlSeconds.
func (db *DB) MarkStaleDevicesOffline(ttlSeconds int64) error {
	cutoff := time.Now().Unix() - ttlSeconds
	_, err := db.Exec(`UPDATE devices SET online = 0 WHERE online = 1 AND last_seen > 0 AND last_seen < ?`, cutoff)
	return err
}

func (db *DB) updateDeviceEndpointInternal(deviceID, endpoint, natType string, relayRTTMS *int64, isHeartbeat bool, expectedRegistrationSequence *int64) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	var currentEndpoint, currentNAT string
	var currentRegSeq, registrationIncarnation int64
	row := tx.QueryRow(`SELECT COALESCE(endpoint, ''), COALESCE(nat_type, ''), COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0) FROM devices WHERE id = ?`, deviceID)
	if err := row.Scan(&currentEndpoint, &currentNAT, &currentRegSeq, &registrationIncarnation); err != nil {
		return err
	}
	if expectedRegistrationSequence != nil && registrationIncarnation > 0 {
		incoming := parseNAT(natType)
		incomingSequence, parseErr := strconv.ParseInt(incoming.lifecycle, 10, 64)
		if *expectedRegistrationSequence != currentRegSeq || !incoming.hasLifecycle || parseErr != nil || incomingSequence != currentRegSeq {
			return &RegistrationSessionConflictError{
				CurrentSequence:    currentRegSeq,
				CurrentIncarnation: registrationIncarnation,
			}
		}
	}

	canOverwrite := shouldOverwriteNAT(currentEndpoint, currentNAT, currentRegSeq, registrationIncarnation > 0, endpoint, natType)

	if canOverwrite {
		if isHeartbeat {
			_, err = tx.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, relay_rtt_ms = ?, last_seen = ?, online = 1 WHERE id = ?`,
				endpoint, natType, relayRTTMS, now, deviceID)
		} else {
			_, err = tx.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, relay_rtt_ms = ? WHERE id = ?`,
				endpoint, natType, relayRTTMS, deviceID)
		}
	} else {
		// Stale / conflicting / unversioned: refresh online presence and relay RTT if heartbeat, but do not overwrite endpoint or nat_type.
		if isHeartbeat {
			_, err = tx.Exec(`UPDATE devices SET relay_rtt_ms = ?, last_seen = ?, online = 1 WHERE id = ?`,
				relayRTTMS, now, deviceID)
		} else {
			_, err = tx.Exec(`UPDATE devices SET relay_rtt_ms = ? WHERE id = ?`,
				relayRTTMS, deviceID)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDeviceEndpoint updates a device's endpoint and NAT type.
func (db *DB) UpdateDeviceEndpoint(deviceID, endpoint, natType string, relayRTTMS *int64) error {
	return db.updateDeviceEndpointInternal(deviceID, endpoint, natType, relayRTTMS, true, nil)
}

// UpdateDeviceEndpointForRegistrationSession updates a device-authenticated
// heartbeat only if it still belongs to the supplied server-issued
// registration sequence.  The check and the lease/RRT mutation share one
// write transaction, so a late daemon cannot renew its lease after a newer
// registration completes between HTTP middleware validation and this update.
func (db *DB) UpdateDeviceEndpointForRegistrationSession(deviceID string, registrationSequence int64, endpoint, natType string, relayRTTMS *int64) error {
	return db.updateDeviceEndpointInternal(deviceID, endpoint, natType, relayRTTMS, true, &registrationSequence)
}

// ReleaseDevicePresence marks a device offline without deleting its
// registration or changing its last real heartbeat. It is used by a graceful
// daemon shutdown; abnormal exits still converge through DeviceOnlineTTL.
func (db *DB) ReleaseDevicePresence(deviceID string) error {
	_, err := db.Exec(`UPDATE devices SET online = 0 WHERE id = ?`, deviceID)
	return err
}

// ReleaseDevicePresenceForRegistrationSession marks a device offline only if
// the request belongs to its current daemon registration sequence.  This
// prevents an older process exiting after its replacement has become online
// from taking the replacement offline.
func (db *DB) ReleaseDevicePresenceForRegistrationSession(deviceID string, registrationSequence int64) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var currentRegSeq, registrationIncarnation int64
	if err := tx.QueryRow(`SELECT COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0) FROM devices WHERE id = ?`, deviceID).
		Scan(&currentRegSeq, &registrationIncarnation); err != nil {
		return err
	}
	if registrationIncarnation > 0 && registrationSequence != currentRegSeq {
		return &RegistrationSessionConflictError{
			CurrentSequence:    currentRegSeq,
			CurrentIncarnation: registrationIncarnation,
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET online = 0 WHERE id = ?`, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDeviceEndpointMetadata updates advertised metadata without asserting a
// live daemon lease. It is used for user-JWT management requests once a device
// has an active device credential; only device-authenticated heartbeats may
// refresh last_seen/online in that state.
func (db *DB) UpdateDeviceEndpointMetadata(deviceID, endpoint, natType string, relayRTTMS *int64) error {
	return db.updateDeviceEndpointInternal(deviceID, endpoint, natType, relayRTTMS, false, nil)
}

// UpdateDeviceName changes the user-visible name of a registered device.
func (db *DB) UpdateDeviceName(deviceID, deviceName string) error {
	_, err := db.Exec(`UPDATE devices SET device_name = ? WHERE id = ?`, deviceName, deviceID)
	return err
}

// UpdateDeviceVirtualIP changes a device's assigned virtual IP after validating the network pool.
func (db *DB) UpdateDeviceVirtualIP(deviceID, virtualIP string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var networkID string
	if err := tx.QueryRow(`SELECT network_id FROM devices WHERE id = ?`, deviceID).Scan(&networkID); err != nil {
		return err
	}
	reservedIP, err := db.reserveVirtualIP(tx, networkID, virtualIP, deviceID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE devices SET virtual_ip = ? WHERE id = ?`, reservedIP, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDevice removes a device.
func (db *DB) DeleteDevice(deviceID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := revokeRoomDeviceTx(tx, deviceID, true); err != nil {
		return err
	}
	return tx.Commit()
}
