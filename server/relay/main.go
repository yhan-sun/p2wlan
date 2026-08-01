package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	server, err := NewRelayServer(config)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}

	if observerAddr := server.UDPObserverAddr(); observerAddr != nil {
		log.Printf("p2wlan relay listening on %s; UDP observer on %s (limits: connections=%d, payload=%d)", server.Addr(), observerAddr, config.MaxConnections, config.MaxFramePayload)
	} else {
		log.Printf("p2wlan relay listening on %s (limits: connections=%d, payload=%d)", server.Addr(), config.MaxConnections, config.MaxFramePayload)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = server.Close()
	}()

	server.Serve()
}
