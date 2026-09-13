package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func controlBindAddress() (string, error) {
	bind := strings.TrimSpace(getEnv("CONTROL_BIND", ":"+getEnv("PORT", "8080")))
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		return "", fmt.Errorf("CONTROL_BIND must be host:port (or set numeric PORT)")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("control port must be between 1 and 65535")
	}
	return bind, nil
}
