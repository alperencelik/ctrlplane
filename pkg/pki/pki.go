// Package pki mints a tenant control plane's CA, certs, keys and kubeconfigs. Serving and client
// certs last a year and are re-issued from the same CA once Current says so; the CA lasts 10y.
// ponytail: no CA rotation; it would invalidate every kubeconfig and needs a trust overlap.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const year = 365 * 24 * time.Hour

// RenewBefore: a cert is re-issued once it has less than this left.
const RenewBefore = 90 * 24 * time.Hour

// Generate returns a fresh tenant PKI keyed by file name: ca.{crt,key},
// apiserver.{crt,key} (SANs = hosts), admin.{crt,key} (system:masters), sa.key,
// and admin.kubeconfig pointing at server with default namespace (may be "").
func Generate(hosts []string, server, namespace string) (map[string][]byte, error) {
	files := map[string][]byte{}

	caKey, caCert, err := issue(nil, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "tenant-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}, 10*year, files, "ca")
	if err != nil {
		return nil, err
	}

	if _, _, err := issue(caKey, caCert, servingTemplate(hosts), year, files, "apiserver"); err != nil {
		return nil, err
	}

	if _, _, err := issue(caKey, caCert, clientTemplate("admin", "system:masters"), year, files, "admin"); err != nil {
		return nil, err
	}

	saKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if files["sa.key"], err = encodeKey(saKey); err != nil {
		return nil, err
	}

	files["admin.kubeconfig"], err = Kubeconfig(server, namespace, files["ca.crt"], files["admin.crt"], files["admin.key"])
	return files, err
}

// ServingCert re-issues the API server's serving cert for hosts with the existing tenant CA.
func ServingCert(caCrtPEM, caKeyPEM []byte, hosts []string) (crt, key []byte, err error) {
	caCert, caKey, err := parseCA(caCrtPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	if _, _, err := issue(caKey, caCert, servingTemplate(hosts), year, files, "s"); err != nil {
		return nil, nil, err
	}
	return files["s.crt"], files["s.key"], nil
}

// SSHKey returns a new PEM SSH host key and its SHA256 fingerprint, in the format
// chisel prints and checks (base64 of sha256 over the wire-format public key).
func SSHKey() (keyPEM []byte, fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pub.Marshal())
	keyPEM, err = encodeKey(key)
	return keyPEM, base64.StdEncoding.EncodeToString(sum[:]), err
}

// Current reports whether the PEM cert is valid for every host and not yet due for renewal
// (RenewBefore): false means re-issue it.
func Current(crtPEM []byte, hosts ...string) bool {
	b, _ := pem.Decode(crtPEM)
	if b == nil {
		return false
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || time.Until(c.NotAfter) < RenewBefore {
		return false
	}
	for _, h := range hosts {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

func servingTemplate(hosts []string) *x509.Certificate {
	t := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "tenant-apiserver"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		} else {
			t.DNSNames = append(t.DNSNames, h)
		}
	}
	return t
}

// ClientCert signs a client cert for user/groups with the tenant CA.
// A user of "system:serviceaccount:<ns>:<name>" is matched by RBAC exactly like that ServiceAccount's token.
func ClientCert(caCrtPEM, caKeyPEM []byte, user string, groups ...string) (crt, key []byte, err error) {
	caCert, caKey, err := parseCA(caCrtPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	files := map[string][]byte{}
	if _, _, err := issue(caKey, caCert, clientTemplate(user, groups...), year, files, "c"); err != nil {
		return nil, nil, err
	}
	return files["c.crt"], files["c.key"], nil
}

// KubeconfigCert is the client cert in a kubeconfig made by Kubeconfig (nil if there's none).
func KubeconfigCert(kubeconfig []byte) []byte {
	kc, err := clientcmd.Load(kubeconfig)
	if err != nil || kc.AuthInfos["user"] == nil {
		return nil
	}
	return kc.AuthInfos["user"].ClientCertificateData
}

// Kubeconfig renders a single-context kubeconfig using client-cert auth.
func Kubeconfig(server, namespace string, ca, crt, key []byte) ([]byte, error) {
	kc := clientcmdapi.NewConfig()
	kc.Clusters["tenant"] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: ca}
	kc.AuthInfos["user"] = &clientcmdapi.AuthInfo{ClientCertificateData: crt, ClientKeyData: key}
	kc.Contexts["tenant"] = &clientcmdapi.Context{Cluster: "tenant", AuthInfo: "user", Namespace: namespace}
	kc.CurrentContext = "tenant"
	return clientcmd.Write(*kc)
}

// ControllerGroup is in the client certs of platform-run controllers, and only there: the
// tenant API server gives full access to its namespace and CRD types to this group, not to every
// ServiceAccount there. Only the platform holds the CA key that can issue it, and ServiceAccount
// tokens never carry it, so a token made for a dashboard or CI can't act as a controller.
const ControllerGroup = "ctrlplane:controllers"

func clientTemplate(user string, groups ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: user, Organization: groups},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// issue creates a key and a cert from tmpl, signed by parent (self-signed if parent is nil),
// and stores PEMs as files[name+".crt"] / files[name+".key"].
func issue(parentKey *ecdsa.PrivateKey, parent, tmpl *x509.Certificate, ttl time.Duration, files map[string][]byte, name string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(ttl)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	files[name+".crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	files[name+".key"], err = encodeKey(key)
	return key, cert, err
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseCA(crtPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(crtPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("pki: invalid CA PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	return cert, key, err
}
