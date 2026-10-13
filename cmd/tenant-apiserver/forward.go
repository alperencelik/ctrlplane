package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

// forward is the tunnel pod's sidecar (`tenant-apiserver forward <listenPort>=<host>:<port>...`):
// each connection to a listen port is dialed to host:port through the tunnel's own SOCKS5
// server on localhost, so controllers reach the tenant's network with no proxy settings.
func forward(socks string, specs []string) error {
	dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return err
	}
	for _, s := range specs {
		port, target, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("forward %q: want <listenPort>=<host>:<port>", s)
		}
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return err
		}
		log.Printf("forwarding :%s to %s via %s", port, target, socks)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					log.Print(err)
					continue
				}
				go pipe(c, dialer, target)
			}
		}()
	}
	select {}
}

func pipe(c net.Conn, dialer proxy.Dialer, target string) {
	defer c.Close()
	r, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("%s: %v", target, err)
		return
	}
	defer r.Close()
	// Either side finishing ends both (the deferred Closes unblock the other Copy).
	go func() { _, _ = io.Copy(r, c); r.Close(); c.Close() }()
	_, _ = io.Copy(c, r)
}
