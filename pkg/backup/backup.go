// Package backup encrypts tenant backups and keeps them in S3-compatible storage.
//
// Layout: s3://<bucket>/<tenantID>/<snapshot>/{db,pki,tenant}.age, where <snapshot> is the
// UTC time it was taken (20061002T150405Z). Every object is encrypted with age, keyed per
// tenant: a passphrase derived from the master key and the tenant ID, so a key handed to one
// tenant's restore can't decrypt another tenant's backups.
package backup

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// SnapshotFormat names snapshots; sorted lexically, they're sorted by time.
const SnapshotFormat = "20060102T150405Z"

// Objects of a snapshot.
const (
	DB     = "db.age"     // the tenant API server's sqlite database
	PKI    = "pki.age"    // the tenant's PKI Secret (CA, service-account key, ...), as JSON
	Tenant = "tenant.age" // the Tenant object, as JSON
)

const partSize = 16 << 20

// workFactor: the passphrase is a 256-bit derived key, not a human password, so scrypt
// doesn't need to be slow.
const workFactor = 10

// TenantKey derives the tenant's backup passphrase from the master key.
func TenantKey(master []byte, tenantID string) (string, error) {
	if len(master) < 32 {
		return "", errors.New("backup key: want at least 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, master, nil, "ctrlplane-backup:"+tenantID, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// Encrypt returns a writer that encrypts to w with key; Close it to finish.
func Encrypt(w io.Writer, key string) (io.WriteCloser, error) {
	r, err := age.NewScryptRecipient(key)
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(workFactor)
	return age.Encrypt(w, r)
}

// Decrypt returns a reader of the plaintext of r. Reads fail if r was tampered with or
// truncated.
func Decrypt(r io.Reader, key string) (io.Reader, error) {
	id, err := age.NewScryptIdentity(key)
	if err != nil {
		return nil, err
	}
	id.SetMaxWorkFactor(workFactor)
	return age.Decrypt(r, id)
}

// Store is the S3-compatible bucket backups go to.
type Store struct {
	c      *minio.Client
	bucket string
}

// StoreConfig: endpoint is host[:port], without scheme.
type StoreConfig struct {
	Endpoint, Bucket, Region, AccessKey, SecretKey string
	Insecure                                       bool // plain HTTP (in-cluster test storage)
}

func NewStore(cfg StoreConfig) (*Store, error) {
	c, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: !cfg.Insecure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, err
	}
	return &Store{c: c, bucket: cfg.Bucket}, nil
}

// EnsureBucket creates the bucket if it doesn't exist.
func (s *Store) EnsureBucket(ctx context.Context) error {
	ok, err := s.c.BucketExists(ctx, s.bucket)
	if err != nil || ok {
		return err
	}
	return s.c.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

// Put encrypts r with key and stores it at name.
func (s *Store) Put(ctx context.Context, name, key string, r io.Reader) error {
	pr, pw := io.Pipe()
	go func() {
		w, err := Encrypt(pw, key)
		if err == nil {
			_, err = io.Copy(w, r)
		}
		if err == nil {
			err = w.Close()
		}
		pw.CloseWithError(err)
	}()
	// Size unknown (streamed): without PartSize, minio-go sizes parts for a 5 TiB object (~550 MiB
	// buffered per part). 16 MiB parts bound memory and still allow objects up to ~156 GiB.
	_, err := s.c.PutObject(ctx, s.bucket, name, pr, -1, minio.PutObjectOptions{ContentType: "application/octet-stream", PartSize: partSize})
	pr.CloseWithError(err) // stop the encrypting goroutine if the upload failed
	return err
}

// Get returns the decrypted object at name; close it when done.
func (s *Store) Get(ctx context.Context, name, key string) (io.ReadCloser, error) {
	obj, err := s.c.GetObject(ctx, s.bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	r, err := Decrypt(obj, key)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return struct {
		io.Reader
		io.Closer
	}{r, obj}, nil
}

// Snapshots lists a tenant's complete snapshots, oldest first: those with a DB object, which
// a backup writes last, so an interrupted backup isn't offered for restore.
func (s *Store) Snapshots(ctx context.Context, tenantID string) ([]string, error) {
	var snaps []string
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: tenantID + "/", Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		if snap, ok := strings.CutSuffix(strings.TrimPrefix(o.Key, tenantID+"/"), "/"+DB); ok {
			snaps = append(snaps, snap)
		}
	}
	slices.Sort(snaps)
	return snaps, nil
}

// Resolve is snapshot if set, else the tenant's latest complete one.
func (s *Store) Resolve(ctx context.Context, tenantID, snapshot string) (string, error) {
	snaps, err := s.Snapshots(ctx, tenantID)
	switch {
	case err != nil:
		return "", err
	case snapshot == "" && len(snaps) > 0:
		return snaps[len(snaps)-1], nil
	case snapshot != "" && slices.Contains(snaps, snapshot):
		return snapshot, nil
	}
	return "", fmt.Errorf("no complete backup %q of tenant %s", snapshot, tenantID)
}

// Prune deletes a tenant's snapshots but the newest keep.
func (s *Store) Prune(ctx context.Context, tenantID string, keep int) error {
	snaps, err := s.Snapshots(ctx, tenantID)
	if err != nil || len(snaps) <= keep {
		return err
	}
	for _, snap := range snaps[:len(snaps)-keep] {
		objs := s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: tenantID + "/" + snap + "/", Recursive: true})
		for e := range s.c.RemoveObjects(ctx, s.bucket, objs, minio.RemoveObjectsOptions{}) {
			if e.Err != nil {
				return e.Err
			}
		}
	}
	return nil
}

// PresignedGet is a URL that downloads name (still encrypted) without credentials, until expiry.
func (s *Store) PresignedGet(ctx context.Context, name string, expiry time.Duration) (string, error) {
	u, err := s.c.PresignedGetObject(ctx, s.bucket, name, expiry, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Name is the object name of a snapshot's object.
func Name(tenantID, snapshot, object string) string { return tenantID + "/" + snapshot + "/" + object }
