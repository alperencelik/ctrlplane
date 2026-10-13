package main

// Backups (pkg/backup): the platform pulls a consistent copy of this API server's sqlite
// database from /platform/snapshot, encrypts it and uploads it; it never gives this pod storage
// credentials. To restore, the platform starts the pod with an init container running
// `tenant-apiserver restore`, which downloads one snapshot through a pre-signed URL and decrypts
// it with this tenant's key, before the API server opens an empty data volume.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite" (kine's own, without cgo)

	"github.com/alperencelik/ctrlplane/pkg/backup"
)

// snapshotHandler serves GET /platform/snapshot: a copy of the database taken by VACUUM INTO,
// which reads it in one transaction, so it's consistent while kine keeps writing. Only the
// platform's admin identity (system:masters) may call it: no tenant role covers the path.
func snapshotHandler(dbPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		tmp := filepath.Join(filepath.Dir(dbPath), fmt.Sprintf(".snapshot-%d.db", time.Now().UnixNano()))
		defer os.Remove(tmp)
		if err := vacuumInto(r.Context(), dbPath, tmp); err != nil {
			http.Error(w, "snapshot: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := os.Open(tmp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.sqlite3")
		_, _ = io.Copy(w, f)
	})
}

func vacuumInto(ctx context.Context, dbPath, out string) error {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(30000)")
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, "VACUUM INTO ?", out)
	return err
}

// restore writes the snapshot at url (encrypted with key) to dbPath, unless dbPath exists:
// a restore only ever fills an empty volume. Without url it does nothing.
func restore(url, key, dbPath string) error {
	if url == "" {
		return nil
	}
	if _, err := os.Stat(dbPath); err == nil {
		fmt.Fprintln(os.Stderr, "restore: database exists, not restoring")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("restore: download: %s", resp.Status)
	}
	plain, err := backup.Decrypt(resp.Body, key)
	if err != nil {
		return err
	}
	tmp := dbPath + ".restoring"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, plain)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dbPath) // atomic: the API server never sees half a database
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("restore: %w", err)
	}
	fmt.Fprintln(os.Stderr, "restore: done")
	return nil
}
