package main

// Backups (pkg/backup). The backupper, on the leader, snapshots every tenant each interval: it
// pulls a consistent copy of the tenant API server's database from /platform/snapshot (with the
// platform's admin credentials), and stores it with the tenant's PKI and Tenant object, each
// encrypted with the tenant's key. Tenant pods never get storage credentials.
//
// Restore: a Tenant with spec.restoreFrom gets the backed-up PKI (same CA and keys: existing
// kubeconfigs and tokens stay valid) and an init container that fills its empty volume from the
// snapshot, through a pre-signed URL and the tenant's key in Secret apiserver-restore. That Secret
// exists only until the restored API server is ready.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
	"github.com/alperencelik/ctrlplane/pkg/backup"
)

const (
	// A backup now, e.g. before a risky change: set it to the current Unix time.
	backupRequestedAnno = "platform.ctrlplane.run/backup-requested"
	restoreSecret       = "apiserver-restore"
	restoreURLExpiry    = time.Hour
	backupRetry         = 5 * time.Minute // after a failed attempt
)

// Metrics for alerts, from the leader: each tenant's newest
// backup (its creation time until the first one) and the interval.
var (
	lastBackup = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "ctrlplane_tenant_last_backup_timestamp_seconds",
		Help: "Time of the tenant's newest backup; its creation time before the first one."}, []string{"tenant"})
	backupInterval = prometheus.NewGauge(prometheus.GaugeOpts{Name: "ctrlplane_backup_interval_seconds",
		Help: "How often each tenant is backed up."})
)

func init() { metrics.Registry.MustRegister(lastBackup, backupInterval) }

// backups is the configuration; nil = backups off.
type backups struct {
	store    *backup.Store
	master   []byte // per-tenant keys derive from it (backup.TenantKey)
	interval time.Duration
	keep     int
}

func (b *backups) key(tenantID string) (string, error) { return backup.TenantKey(b.master, tenantID) }

// backupsFromEnv reads BACKUP_*; nil without a bucket.
func backupsFromEnv() (*backups, error) {
	bucket := env("BACKUP_S3_BUCKET", "")
	if bucket == "" {
		return nil, nil
	}
	master, err := base64.StdEncoding.DecodeString(env("BACKUP_KEY", ""))
	if err != nil || len(master) < 32 {
		return nil, errors.New("BACKUP_KEY: want base64 of at least 32 random bytes (openssl rand -base64 32)")
	}
	interval, err := time.ParseDuration(env("BACKUP_INTERVAL", "6h"))
	if err != nil {
		return nil, fmt.Errorf("BACKUP_INTERVAL: %w", err)
	}
	keep, err := strconv.Atoi(env("BACKUP_KEEP", "28"))
	if err != nil || keep < 1 {
		return nil, errors.New("BACKUP_KEEP: want a positive number")
	}
	store, err := backup.NewStore(backup.StoreConfig{Endpoint: env("BACKUP_S3_ENDPOINT", "s3.amazonaws.com"), Bucket: bucket,
		Region: env("BACKUP_S3_REGION", ""), AccessKey: env("BACKUP_S3_ACCESS_KEY", ""), SecretKey: env("BACKUP_S3_SECRET_KEY", ""),
		Insecure: env("BACKUP_S3_INSECURE", "") == "true"})
	if err != nil {
		return nil, err
	}
	return &backups{store: store, master: master, interval: interval, keep: keep}, nil
}

// backupper is a manager Runnable on the leader.
type backupper struct {
	client.Client
	b          *backups
	platformNS string
	failed     map[string]time.Time // tenant -> its last failed attempt (this leader's)
}

func (bk *backupper) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("backup")
	bk.failed = map[string]time.Time{}
	if err := bk.b.store.EnsureBucket(ctx); err != nil {
		log.Error(err, "backup bucket") // each attempt reports its own error too
	}
	backupInterval.Set(bk.b.interval.Seconds())
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		tenants := &platformv1alpha1.TenantList{}
		if err := bk.List(ctx, tenants); err != nil {
			log.Error(err, "list tenants")
		} else {
			lastBackup.Reset() // drops deleted tenants
		}
		for i := range tenants.Items {
			t := &tenants.Items[i]
			last := t.CreationTimestamp.Time
			if b := t.Status.Backup; b != nil && b.Time != nil {
				last = b.Time.Time
			}
			lastBackup.WithLabelValues(t.Name).Set(float64(last.Unix()))
			if !bk.due(t, time.Now()) {
				continue
			}
			snap, err := bk.backup(ctx, t)
			st := &platformv1alpha1.BackupStatus{}
			if t.Status.Backup != nil {
				st = t.Status.Backup.DeepCopy()
			}
			if err != nil {
				log.Error(err, "backup", "tenant", t.Name)
				st.Error = err.Error()
				bk.failed[t.Name] = time.Now()
			} else {
				delete(bk.failed, t.Name)
				now := metav1.Now()
				st.Snapshot, st.Time, st.Error = snap, &now, ""
				lastBackup.WithLabelValues(t.Name).Set(float64(now.Unix()))
			}
			patch := client.MergeFrom(t.DeepCopy())
			t.Status.Backup = st
			if err := bk.Status().Patch(ctx, t, patch); err != nil {
				log.Error(err, "backup status", "tenant", t.Name)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// due: the tenant is up, and its last backup is older than the interval or than a request.
// A failed attempt is retried after backupRetry.
func (bk *backupper) due(t *platformv1alpha1.Tenant, now time.Time) bool {
	if t.DeletionTimestamp != nil || t.Status.Endpoint == "" {
		return false
	}
	requested, _ := strconv.ParseInt(t.Annotations[backupRequestedAnno], 10, 64)
	// After a failure, wait backupRetry, unless someone asks again after it.
	if f, ok := bk.failed[t.Name]; ok && now.Sub(f) < backupRetry && !time.Unix(requested, 0).After(f) {
		return false
	}
	var last time.Time
	if b := t.Status.Backup; b != nil && b.Time != nil {
		last = b.Time.Time
	}
	return now.Sub(last) >= bk.b.interval || time.Unix(requested, 0).After(last)
}

// backup stores one snapshot of t and prunes old ones; it returns the snapshot's name.
func (bk *backupper) backup(ctx context.Context, t *platformv1alpha1.Tenant) (string, error) {
	id := t.Status.ID
	key, err := bk.b.key(id)
	if err != nil {
		return "", err
	}
	pkiSecret := &corev1.Secret{}
	if err := bk.Get(ctx, client.ObjectKey{Namespace: bk.platformNS, Name: t.Name + "-tenant-pki"}, pkiSecret); err != nil {
		return "", err
	}
	snap := time.Now().UTC().Format(backup.SnapshotFormat)
	pkiJSON, err := json.Marshal(pkiSecret.Data)
	if err != nil {
		return "", err
	}
	tenantJSON, err := json.Marshal(platformv1alpha1.Tenant{TypeMeta: metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: "Tenant"},
		ObjectMeta: metav1.ObjectMeta{Name: t.Name, Labels: t.Labels}, Spec: t.Spec})
	if err != nil {
		return "", err
	}
	if err := bk.b.store.Put(ctx, backup.Name(id, snap, backup.PKI), key, bytes.NewReader(pkiJSON)); err != nil {
		return "", err
	}
	if err := bk.b.store.Put(ctx, backup.Name(id, snap, backup.Tenant), key, bytes.NewReader(tenantJSON)); err != nil {
		return "", err
	}
	db, err := snapshotDB(ctx, pkiSecret.Data["admin.kubeconfig"], fmt.Sprintf("https://apiserver.tenant-%s.svc:%d", t.Name, apiserverPort))
	if err != nil {
		return "", err
	}
	defer db.Close()
	// Last: a snapshot counts once its DB is stored (backup.Store.Snapshots).
	if err := bk.b.store.Put(ctx, backup.Name(id, snap, backup.DB), key, db); err != nil {
		return "", err
	}
	return snap, bk.b.store.Prune(ctx, id, bk.b.keep)
}

// snapshotDB streams the database of the tenant API server that kubeconfig (its admin) reaches.
// snapshotDB fetches the tenant API server's database through its in-cluster Service (server;
// NetworkPolicy platform-to-apiserver), not the public endpoint: that path goes out through the
// Gateway's load balancer, which a cluster may not route back to (or slowly).
func snapshotDB(ctx context.Context, kubeconfig []byte, server string) (io.ReadCloser, error) {
	cfg, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	cfg.Host = server
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Host+"/platform/snapshot", nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("snapshot: %s: %s", resp.Status, b)
	}
	return resp.Body, nil
}

// restoreSnapshot is the snapshot spec.restoreFrom resolves to, resolved once (status).
func (r *reconciler) restoreSnapshot(ctx context.Context, t *platformv1alpha1.Tenant) (string, error) {
	if r.backups == nil {
		return "", errors.New("spec.restoreFrom: backups aren't configured")
	}
	if t.Status.RestoredSnapshot != "" {
		return t.Status.RestoredSnapshot, nil
	}
	return r.backups.store.Resolve(ctx, t.Spec.RestoreFrom.TenantID, t.Spec.RestoreFrom.Snapshot)
}

// restoredPKI is the backed-up PKI of spec.restoreFrom.
func (r *reconciler) restoredPKI(ctx context.Context, t *platformv1alpha1.Tenant, snap string) (map[string][]byte, error) {
	from := t.Spec.RestoreFrom.TenantID
	key, err := r.backups.key(from)
	if err != nil {
		return nil, err
	}
	obj, err := r.backups.store.Get(ctx, backup.Name(from, snap, backup.PKI), key)
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	files := map[string][]byte{}
	return files, json.NewDecoder(obj).Decode(&files)
}

// reconcileRestore keeps Secret apiserver-restore (a fresh pre-signed URL to the snapshot's
// database and the source tenant's key) until the restored API server is ready, then deletes
// it. It returns when to look again.
func (r *reconciler) reconcileRestore(ctx context.Context, t *platformv1alpha1.Tenant, ns, snap string, owner *metav1ac.OwnerReferenceApplyConfiguration) (time.Duration, error) {
	sts := &appsv1.StatefulSet{}
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: "apiserver"}, sts)
	if err == nil && sts.Status.ReadyReplicas > 0 {
		return 0, client.IgnoreNotFound(r.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: restoreSecret}}))
	}
	from := t.Spec.RestoreFrom.TenantID
	key, err := r.backups.key(from)
	if err != nil {
		return 0, err
	}
	url, err := r.backups.store.PresignedGet(ctx, backup.Name(from, snap, backup.DB), restoreURLExpiry)
	if err != nil {
		return 0, err
	}
	return restoreURLExpiry / 2, r.Apply(ctx, corev1ac.Secret(restoreSecret, ns).WithOwnerReferences(owner).
		WithStringData(map[string]string{"RESTORE_URL": url, "RESTORE_KEY": key}), fieldOwner, client.ForceOwnership)
}
