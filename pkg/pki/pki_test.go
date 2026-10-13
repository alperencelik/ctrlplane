package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func cert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPKI(t *testing.T) {
	files, err := Generate([]string{"apiserver.tenant-x.svc", "127.0.0.1"}, "https://apiserver.tenant-x.svc:6443", "x")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert(t, files["ca.crt"]))

	serving := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, host := range []string{"apiserver.tenant-x.svc", "127.0.0.1"} {
		serving.DNSName = host
		if _, err := cert(t, files["apiserver.crt"]).Verify(serving); err != nil {
			t.Errorf("serving cert for %s: %v", host, err)
		}
	}
	serving.DNSName = "apiserver.other-tenant.svc"
	if _, err := cert(t, files["apiserver.crt"]).Verify(serving); err == nil {
		t.Error("serving cert must not be valid for another host")
	}

	if !Current(files["apiserver.crt"], "apiserver.tenant-x.svc", "127.0.0.1") || Current(files["apiserver.crt"], "abc.api.example.com") {
		t.Error("Current wrong for the generated serving cert")
	}
	reissued, _, err := ServingCert(files["ca.crt"], files["ca.key"], []string{"apiserver.tenant-x.svc", "abc.api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	serving.DNSName = "abc.api.example.com"
	if _, err := cert(t, reissued).Verify(serving); err != nil || !Current(reissued, "abc.api.example.com") {
		t.Errorf("re-issued serving cert must chain to the same CA and cover the new host: %v", err)
	}

	// Within RenewBefore of expiry: due for renewal, though still valid.
	caCert, caKey, err := parseCA(files["ca.crt"], files["ca.key"])
	if err != nil {
		t.Fatal(err)
	}
	soon := map[string][]byte{}
	if _, _, err := issue(caKey, caCert, servingTemplate([]string{"x"}), 30*24*time.Hour, soon, "s"); err != nil {
		t.Fatal(err)
	}
	if Current(soon["s.crt"], "x") || !Current(files["admin.crt"]) {
		t.Error("Current must be false within RenewBefore of expiry, true for a fresh cert")
	}
	kc, err := Kubeconfig("https://x", "", files["ca.crt"], files["admin.crt"], files["admin.key"])
	if err != nil || string(KubeconfigCert(kc)) != string(files["admin.crt"]) {
		t.Errorf("KubeconfigCert: %v", err)
	}

	crt, _, err := ClientCert(files["ca.crt"], files["ca.key"], "system:serviceaccount:ns:sa", "system:serviceaccounts")
	if err != nil {
		t.Fatal(err)
	}
	c := cert(t, crt)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client cert: %v", err)
	}
	if c.Subject.CommonName != "system:serviceaccount:ns:sa" || c.Subject.Organization[0] != "system:serviceaccounts" {
		t.Errorf("client cert subject = %v", c.Subject)
	}

	other, _ := Generate([]string{"x"}, "https://x", "")
	if _, err := c.Verify(x509.VerifyOptions{Roots: func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(cert(t, other["ca.crt"])); return p }(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("client cert must not verify against another tenant's CA")
	}
}
