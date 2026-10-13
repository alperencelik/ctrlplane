package main

import (
	"context"
	"strconv"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

func TestBackupDue(t *testing.T) {
	now := time.Now()
	bk := &backupper{b: &backups{interval: 6 * time.Hour}, failed: map[string]time.Time{"failing": now.Add(-time.Minute)}}
	at := func(ago time.Duration) *platformv1alpha1.BackupStatus {
		ts := metav1.NewTime(now.Add(-ago))
		return &platformv1alpha1.BackupStatus{Snapshot: "s", Time: &ts}
	}
	tenant := func(name string, b *platformv1alpha1.BackupStatus, requested time.Duration) *platformv1alpha1.Tenant {
		t := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: platformv1alpha1.TenantStatus{Endpoint: "https://x", Backup: b}}
		if requested != 0 {
			t.Annotations = map[string]string{backupRequestedAnno: strconv.FormatInt(now.Add(-requested).Unix(), 10)}
		}
		return t
	}
	for name, tc := range map[string]struct {
		t   *platformv1alpha1.Tenant
		due bool
	}{
		"never backed up":                 {tenant("a", nil, 0), true},
		"backed up recently":              {tenant("a", at(time.Hour), 0), false},
		"older than the interval":         {tenant("a", at(7*time.Hour), 0), true},
		"requested after the last":        {tenant("a", at(time.Hour), time.Minute), true},
		"requested before the last":       {tenant("a", at(time.Hour), 2*time.Hour), false},
		"failed a minute ago":             {tenant("failing", nil, 0), false},
		"requested again after it failed": {tenant("failing", nil, 30*time.Second), true},
		"requested before it failed":      {tenant("failing", nil, 2*time.Minute), false},
		"not up yet":                      {&platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "a"}}, false},
	} {
		if got := bk.due(tc.t, now); got != tc.due {
			t.Errorf("%s: due = %v, want %v", name, got, tc.due)
		}
	}
}

// spec.restoreFrom is set at creation only.
func TestRestoreFromOnlyAtCreation(t *testing.T) {
	ctx := context.Background()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "late-restore"}}
	if err := k8sClient.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	patch := client.MergeFrom(tenant.DeepCopy())
	tenant.Spec.RestoreFrom = &platformv1alpha1.RestoreSpec{TenantID: "abcdefghij"}
	if err := k8sClient.Patch(ctx, tenant, patch); !apierrors.IsInvalid(err) {
		t.Fatalf("adding restoreFrom later: want Invalid, got %v", err)
	}
}
