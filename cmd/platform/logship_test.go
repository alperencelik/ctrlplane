package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

func TestEventLine(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	e := &eventsv1.Event{
		EventTime: metav1.NewMicroTime(at.Add(-time.Hour)), Series: &eventsv1.EventSeries{Count: 3, LastObservedTime: metav1.NewMicroTime(at)},
		ReportingController: "vm-watcher", Action: "Reconcile", Reason: "Failed", Type: "Warning", Note: "VM web-1 failed",
		Regarding: corev1.ObjectReference{Kind: "VirtualMachine", Namespace: "acme", Name: "web-1"},
	}
	b, _ := json.Marshal(newEventLine("tenant-acme", e))
	want := `{"_msg":"VM web-1 failed","_time":"2026-10-04T12:00:00Z","ctrlplane_tenant":"tenant-acme","ctrlplane_source":"events",` +
		`"type":"Warning","reason":"Failed","action":"Reconcile","regarding_kind":"VirtualMachine","regarding_namespace":"acme",` +
		`"regarding_name":"web-1","reporting_controller":"vm-watcher","count":3}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

// TestEventShipper: the test API server stands in for a tenant API server, httptest for VictoriaLogs.
func TestEventShipper(t *testing.T) {
	since := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	var mu sync.Mutex
	var queries, shipped []string
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/select/logsql/query":
			queries = append(queries, r.FormValue("query"))
			fmt.Fprintf(w, `{"t":%q}`+"\n", since.Format(time.RFC3339Nano))
		case "/insert/jsonline":
			if f := r.URL.Query().Get("_stream_fields"); f != "ctrlplane_tenant,ctrlplane_source" {
				t.Errorf("stream fields %q", f)
			}
			for sc := bufio.NewScanner(r.Body); sc.Scan(); {
				shipped = append(shipped, sc.Text())
			}
		}
	}))
	defer vl.Close()
	tenant := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "evts"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "platform-system", Name: "evts-tenant-pki"},
			Data: map[string][]byte{"admin.kubeconfig": []byte("kc")}},
		&platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "provisioning"}}, // no kubeconfig yet
	).Build()
	s := &eventShipper{Reader: c, platformNS: "platform-system", vl: vl.URL, http: vl.Client(),
		config:  func(kc []byte, tenant string) (*rest.Config, error) { return restCfg, nil },
		running: map[string]tenantWatch{}, lines: make(chan eventLine, 1000)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ship(ctx)
	s.sync(ctx)
	if len(s.running) != 1 || s.running["evts"].kubeconfig != "kc" {
		t.Fatalf("running %v, want only evts", s.running)
	}

	cs := kubernetes.NewForConfigOrDie(restCfg)
	for name, at := range map[string]time.Time{"old": since.Add(-time.Minute), "new": time.Now()} {
		_, err := cs.EventsV1().Events("default").Create(ctx, &eventsv1.Event{ObjectMeta: metav1.ObjectMeta{Name: "evts-" + name},
			EventTime: metav1.NewMicroTime(at), ReportingController: "test", ReportingInstance: "test-0", Action: "Test", Reason: "Test",
			Type: "Normal", Note: name, Regarding: corev1.ObjectReference{Kind: "Widget", Name: "evts-" + name}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() error {
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(strings.Join(shipped, "\n"), `"regarding_name":"evts-new"`) {
			return fmt.Errorf("shipped %v", shipped)
		}
		return nil
	})
	mu.Lock()
	for _, l := range shipped {
		if strings.Contains(l, `"evts-old"`) {
			t.Errorf("shipped an event older than the newest stored one: %s", l)
		}
		if !strings.Contains(l, `"ctrlplane_tenant":"tenant-evts"`) {
			t.Errorf("not tenant-evts: %s", l)
		}
	}
	if want := `{ctrlplane_tenant="tenant-evts",ctrlplane_source="events"} | stats max(_time) as t`; len(queries) != 1 || queries[0] != want {
		t.Errorf("resume queries %q, want [%q]", queries, want)
	}
	mu.Unlock()

	// A re-issued admin kubeconfig restarts the informer; a deleted tenant stops it.
	stopped := false
	s.running["evts"] = tenantWatch{kubeconfig: "old", stop: func() { stopped = true }}
	s.sync(ctx)
	if !stopped || s.running["evts"].kubeconfig != "kc" {
		t.Errorf("changed kubeconfig: stopped %v, running %v", stopped, s.running)
	}
	stopped = false
	s.running["evts"] = tenantWatch{kubeconfig: "kc", stop: func() { stopped = true }}
	if err := c.Delete(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	s.sync(ctx)
	if !stopped || len(s.running) != 0 {
		t.Errorf("deleted tenant: stopped %v, running %v", stopped, s.running)
	}
}
