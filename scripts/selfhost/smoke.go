// An isolated authenticated two-process smoke test; never touches installed services.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type client struct {
	base string
	http *http.Client
}

func (c client) request(method, path, token, seq string, body any) (map[string]any, error) {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if seq != "" {
		req.Header.Set("X-P2WLAN-Registration-Seq", seq)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s returned HTTP %d", method, path, resp.StatusCode)
	}
	result := map[string]any{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}
func loadEnv(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env []string
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if !strings.HasPrefix(k, "RELAY_") && !strings.HasPrefix(k, "CONTROL_") && k != "JWT_SECRET" && k != "DB_PATH" && k != "PORT" && k != "LOG_UPLOAD_DIR" {
			env = append(env, v)
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" {
			env = append(env, line)
		}
	}
	return env, nil
}
func text(m map[string]any, key string) string { s, _ := m[key].(string); return s }
func freePort(host string) (int, error) {
	l, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func waitHTTP(url string, want int) error {
	c := http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r, e := c.Get(url)
		if e == nil {
			r.Body.Close()
			if r.StatusCode == want {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("readiness did not reach HTTP %d at %s", want, url)
}
func writeFrame(conn net.Conn, kind byte, payload []byte) error {
	header := []byte{'D', 'E', 'R', 'P', 1, kind, 0, 0}
	binary.BigEndian.PutUint16(header[6:], uint16(len(payload)))
	_, err := io.Copy(conn, bytes.NewReader(append(header, payload...)))
	return err
}
func readFrame(conn net.Conn) (byte, []byte, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, 8)
	if _, err := io.ReadFull(conn, h); err != nil {
		return 0, nil, err
	}
	if string(h[:4]) != "DERP" || h[4] != 1 {
		return 0, nil, errors.New("invalid relay header")
	}
	p := make([]byte, binary.BigEndian.Uint16(h[6:]))
	_, err := io.ReadFull(conn, p)
	return h[5], p, err
}
func register(c client, account string) (node, credential, sequence string, err error) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		err = e
		return
	}
	m, e := c.request("POST", "/api/v1/devices", account, "", map[string]any{"public_key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "device_name": "selfhost smoke", "platform": "test", "network_id": "default", "registration_incarnation": 1})
	if e != nil {
		err = e
		return
	}
	node = text(m, "node_id")
	seq, _ := m["registration_seq"].(float64)
	sequence = strconv.FormatInt(int64(seq), 10)
	challenge, e := c.request("POST", "/api/v1/challenges", account, "", map[string]string{"device_id": node})
	if e != nil {
		err = e
		return
	}
	raw, e := hex.DecodeString(text(challenge, "challenge"))
	if e != nil {
		err = e
		return
	}
	m, e = c.request("POST", "/api/v1/devices/credential", account, "", map[string]string{"device_id": node, "ed25519_public_key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "challenge_id": text(challenge, "challenge_id"), "challenge_signature": hex.EncodeToString(ed25519.Sign(key, raw))})
	if e != nil {
		err = e
		return
	}
	credential = text(m, "device_credential")
	if node == "" || credential == "" {
		err = errors.New("missing device identity")
	}
	return
}
func run(binDir, relayHost string) error {
	if relayHost != "localhost" && !net.ParseIP(relayHost).IsLoopback() {
		return errors.New("--relay-host must be localhost or a loopback IP")
	}
	dir, err := os.MkdirTemp("", "p2wlan-selfhost-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	binaryPath := func(name string) string { return filepath.Join(binDir, "p2wlan-"+name+suffix) }
	ports := []int{}
	for len(ports) < 3 {
		host := "127.0.0.1"
		if len(ports) == 1 && relayHost != "localhost" {
			host = relayHost
		}
		p, e := freePort(host)
		if e != nil {
			return e
		}
		unique := true
		for _, old := range ports {
			if p == old {
				unique = false
			}
		}
		if unique {
			ports = append(ports, p)
		}
	}
	cfg := filepath.Join(dir, "config")
	cmd := exec.Command(binaryPath("config"), "--output", cfg, "--dev-localhost", "--relay-endpoint", "tls://"+net.JoinHostPort(relayHost, strconv.Itoa(ports[1])), "--control-port", strconv.Itoa(ports[0]), "--metrics-port", strconv.Itoa(ports[2]))
	if output, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("configuration bootstrap failed: %s: %w", output, e)
	}
	for _, role := range []string{"control", "relay"} {
		env, e := loadEnv(filepath.Join(cfg, role+".env"))
		if e != nil {
			return e
		}
		log, e := os.Create(filepath.Join(dir, role+".log"))
		if e != nil {
			return e
		}
		defer log.Close()
		cmd = exec.Command(binaryPath(role))
		cmd.Env = env
		cmd.Dir = dir
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			return e
		}
		process := cmd
		defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", ports[0])
	ready := fmt.Sprintf("http://127.0.0.1:%d/readyz", ports[2])
	if err = waitHTTP(base+"/health", 200); err != nil {
		return err
	}
	if err = waitHTTP(ready, 200); err != nil {
		return err
	}
	fmt.Println("PASS: generated configuration, SQLite, control health, revocation-backed relay readiness")
	c := client{base, &http.Client{Timeout: 5 * time.Second}}
	pass := make([]byte, 20)
	if _, err = rand.Read(pass); err != nil {
		return err
	}
	m, err := c.request("POST", "/api/v1/register", "", "", map[string]string{"email": "smoke@example.test", "password": hex.EncodeToString(pass)})
	if err != nil {
		return err
	}
	account := text(m, "token")
	if account == "" {
		return errors.New("missing account token")
	}
	cert, err := os.ReadFile(filepath.Join(cfg, "tls.crt"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return errors.New("test certificate could not be trusted")
	}
	var ids []string
	var connections []net.Conn
	for i := 0; i < 2; i++ {
		node, credential, seq, e := register(c, account)
		if e != nil {
			return e
		}
		ids = append(ids, node)
		issued, e := c.request("POST", "/api/v1/relay/tickets", credential, seq, map[string]string{"audience": "selfhost-relay-1"})
		if e != nil {
			return e
		}
		ticket := []byte(text(issued, "ticket"))
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort(relayHost, strconv.Itoa(ports[1])), &tls.Config{RootCAs: roots, ServerName: relayHost, MinVersion: tls.VersionTLS13})
		if e != nil {
			return e
		}
		defer conn.Close()
		connections = append(connections, conn)
		payload := append([]byte{byte(len(node))}, []byte(node)...)
		size := make([]byte, 2)
		binary.BigEndian.PutUint16(size, uint16(len(ticket)))
		payload = append(payload, size...)
		payload = append(payload, ticket...)
		if e = writeFrame(conn, 9, payload); e != nil {
			return e
		}
		kind, p, e := readFrame(conn)
		if e != nil {
			return e
		}
		if kind != 2 || string(p) != node {
			return errors.New("authenticated TLS registration rejected")
		}
	}
	payload := []byte("selfhost forwarding proof")
	if err = writeFrame(connections[0], 3, append(append([]byte{byte(len(ids[1]))}, []byte(ids[1])...), payload...)); err != nil {
		return err
	}
	kind, p, err := readFrame(connections[1])
	if err != nil {
		return err
	}
	if kind != 4 || len(p) < 1+len(ids[0]) || string(p[1:1+len(ids[0])]) != ids[0] || !bytes.Equal(p[1+len(ids[0]):], payload) {
		return errors.New("forwarded frame mismatch")
	}
	fmt.Println("PASS: account, device challenge, tickets, TLS verification, authenticated relay forwarding")
	req, _ := http.NewRequest("DELETE", base+"/api/v1/devices/"+ids[1], nil)
	req.Header.Set("Authorization", "Bearer "+account)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("device revocation failed")
	}
	_ = connections[1].SetReadDeadline(time.Now().Add(12 * time.Second))
	_, err = connections[1].Read(make([]byte, 1))
	if err == nil {
		return errors.New("revoked relay connection remained open")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return errors.New("revocation did not close connection within the test bound")
	}
	fmt.Println("PASS: revocation feed disconnects an existing authenticated relay peer")
	return nil
}
func main() {
	dir := flag.String("bin-dir", "", "Directory containing control, relay and config binaries")
	relayHost := flag.String("relay-host", "localhost", "Loopback host advertised by and used to dial the generated deployment")
	flag.Parse()
	absolute, err := filepath.Abs(*dir)
	if err == nil && *dir != "" {
		err = run(absolute, *relayHost)
	} else {
		err = errors.New("--bin-dir is required")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "selfhost smoke:", err)
		os.Exit(1)
	}
}
