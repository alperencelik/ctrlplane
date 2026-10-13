package main

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alperencelik/ctrlplane/pkg/backup"
)

// A snapshot taken from /platform/snapshot, encrypted, restores to the same data, and a restore
// never overwrites an existing database.
func TestSnapshotRestore(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "tenant.db")
	db, err := sql.Open("sqlite", "file:"+src+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE kine (name TEXT, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"/registry/a", "/registry/b"} {
		if _, err := db.Exec(`INSERT INTO kine VALUES (?, ?)`, n, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	snapshotHandler(src).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/snapshot", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot: %d %s", rec.Code, rec.Body)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".snapshot-*")); len(left) != 0 {
		t.Fatalf("temporary snapshot left behind: %v", left)
	}

	key, _ := backup.TenantKey(bytes.Repeat([]byte{7}, 32), "tenantid")
	var sealed bytes.Buffer
	w, _ := backup.Encrypt(&sealed, key)
	_, _ = io.Copy(w, rec.Body)
	_ = w.Close()
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sealed.Bytes()) }))
	defer store.Close()

	dst := filepath.Join(t.TempDir(), "tenant.db")
	if err := restore(store.URL, key, dst); err != nil {
		t.Fatal(err)
	}
	restored, err := sql.Open("sqlite", "file:"+dst)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var n int
	if err := restored.QueryRow(`SELECT count(*) FROM kine`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("restored rows = %d, %v", n, err)
	}

	before, _ := os.ReadFile(dst)
	if err := restore(store.URL, "wrong key, but never used", dst); err != nil {
		t.Fatalf("restore over an existing database: %v", err)
	}
	if after, _ := os.ReadFile(dst); !bytes.Equal(before, after) {
		t.Fatal("restore overwrote an existing database")
	}

	empty := filepath.Join(t.TempDir(), "tenant.db")
	if err := restore(store.URL, "wrong", empty); err == nil {
		t.Fatal("restore with the wrong key succeeded")
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Fatal("failed restore left a database behind")
	}
}
