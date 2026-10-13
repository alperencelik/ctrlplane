package backup

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	keyA, err := TenantKey(master, "tenanta")
	if err != nil {
		t.Fatal(err)
	}
	keyB, _ := TenantKey(master, "tenantb")
	if keyA == keyB {
		t.Fatal("tenants share a key")
	}
	if again, _ := TenantKey(master, "tenanta"); again != keyA {
		t.Fatal("key derivation isn't deterministic")
	}
	if _, err := TenantKey(master[:16], "tenanta"); err == nil {
		t.Fatal("short master key accepted")
	}

	plain := make([]byte, 3<<20+123) // several age chunks (64 KiB) plus a partial one
	_, _ = rand.Read(plain)
	var sealed bytes.Buffer
	w, err := Encrypt(&sealed, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Bytes(), plain[:64]) {
		t.Fatal("plaintext visible in the ciphertext")
	}

	read := func(data []byte, key string) ([]byte, error) {
		r, err := Decrypt(bytes.NewReader(data), key)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}
	if got, err := read(sealed.Bytes(), keyA); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := read(sealed.Bytes(), keyB); err == nil {
		t.Fatal("another tenant's key decrypted it")
	}
	tampered := bytes.Clone(sealed.Bytes())
	tampered[len(tampered)/2] ^= 1
	if _, err := read(tampered, keyA); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	if _, err := read(sealed.Bytes()[:sealed.Len()-70000], keyA); err == nil {
		t.Fatal("truncated ciphertext decrypted")
	}
}
