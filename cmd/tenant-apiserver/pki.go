package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/alperencelik/ctrlplane/pkg/pki"
)

const pkiDir = "pki"

func pkiPath(name string) string { return filepath.Join(pkiDir, name) }

// ensurePKI writes a fresh PKI into ./pki on first standalone start. When hosted,
// the platform mounts pki/ from a Secret (without ca.key), so this is a no-op.
// ponytail: changing --tenant-hosts later needs `rm -r pki`.
func ensurePKI(hosts []string, port int, namespace string) error {
	if _, err := os.Stat(pkiPath("ca.crt")); err == nil {
		return nil
	}
	files, err := pki.Generate(hosts, "https://"+net.JoinHostPort(hosts[0], strconv.Itoa(port)), namespace)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(pkiPath(name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
