package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

var (
	logshipErrors = prometheus.NewCounter(prometheus.CounterOpts{Name: "ctrlplane_logship_errors_total",
		Help: "Failed writes of controller log batches to VictoriaLogs (retried)."})
	eventshipErrors = prometheus.NewCounter(prometheus.CounterOpts{Name: "ctrlplane_eventship_errors_total",
		Help: "Failed writes of tenant event batches to VictoriaLogs (retried)."})
)

func init() { metrics.Registry.MustRegister(logshipErrors, eventshipErrors) }

// logShipper follows the "controller" container of every tenant controller pod through the
// Kubernetes API (like kubectl logs -f).
// NOTE: log volume flows through the host API server; move to a node agent reading
// /var/log/pods when that gets heavy.
type logShipper struct {
	cs      kubernetes.Interface
	vl      string // VictoriaLogs base URL
	http    *http.Client
	mu      sync.Mutex
	running map[string]context.CancelFunc // pod UID -> its follower
}

func (s *logShipper) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("logship")
	s.running = map[string]context.CancelFunc{}
	f := informers.NewSharedInformerFactoryWithOptions(s.cs, 10*time.Minute,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = labelController }))
	track := func(obj any) {
		p, ok := obj.(*corev1.Pod)
		if !ok || !strings.HasPrefix(p.Namespace, "tenant-") {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		uid := string(p.UID)
		if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			if stop, ok := s.running[uid]; ok {
				stop()
				delete(s.running, uid)
			}
			return
		}
		if _, ok := s.running[uid]; ok || p.Status.Phase != corev1.PodRunning {
			return
		}
		pctx, stop := context.WithCancel(ctx)
		s.running[uid] = stop
		go s.follow(pctx, p.Namespace, p.Name, p.Labels[labelController], log)
	}
	_, _ = f.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: track, UpdateFunc: func(_, o any) { track(o) },
		DeleteFunc: func(o any) {
			if d, ok := o.(cache.DeletedFinalStateUnknown); ok {
				o = d.Obj
			}
			if p, ok := o.(*corev1.Pod); ok {
				s.mu.Lock()
				if stop, ok := s.running[string(p.UID)]; ok {
					stop()
					delete(s.running, string(p.UID))
				}
				s.mu.Unlock()
			}
		},
	})
	f.Start(ctx.Done())
	<-ctx.Done()
	return nil
}

// follow streams one pod's controller container, reopening after container restarts,
// until ctx ends (pod gone).
func (s *logShipper) follow(ctx context.Context, ns, pod, controller string, log interface{ Error(error, string, ...any) }) {
	since := resumeAfter(ctx, s.http, s.vl, fmt.Sprintf(`{ctrlplane_tenant=%q,ctrlplane_pod=%q}`, ns, pod), logshipErrors, log, "pod", ns+"/"+pod)
	for ctx.Err() == nil {
		opts := &corev1.PodLogOptions{Container: "controller", Follow: true, Timestamps: true}
		if !since.IsZero() {
			t := metav1.NewTime(since)
			opts.SinceTime = &t
		}
		stream, err := s.cs.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
		if err == nil {
			since = s.ship(ctx, stream, ns, pod, controller, since, log)
			stream.Close()
		}
		select { // container restarting, or not started yet
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

type logLine struct {
	Msg        string    `json:"_msg"`
	Time       time.Time `json:"_time"`
	Tenant     string    `json:"ctrlplane_tenant"`
	Controller string    `json:"ctrlplane_controller"`
	Pod        string    `json:"ctrlplane_pod"`
}

// ship posts lines in batches (every second or 500 lines) and returns the newest time shipped.
// SinceTime has one-second resolution, so lines at or before the resume point are skipped.
func (s *logShipper) ship(ctx context.Context, r io.Reader, ns, pod, controller string, since time.Time, log interface{ Error(error, string, ...any) }) time.Time {
	lines := make(chan logLine, 1000)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			ts, msg, _ := strings.Cut(sc.Text(), " ")
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil || !t.After(since) {
				continue
			}
			lines <- logLine{Msg: msg, Time: t, Tenant: ns, Controller: controller, Pod: pod}
		}
	}()
	batches(ctx, lines, func(b []logLine) bool {
		if err := vlInsert(ctx, s.http, s.vl, "ctrlplane_tenant,ctrlplane_controller,ctrlplane_pod", b); err != nil {
			log.Error(err, "ship logs", "pod", ns+"/"+pod)
			logshipErrors.Inc()
			return false
		}
		since = b[len(b)-1].Time
		return true
	})
	return since
}

// batches posts what arrives on in every second or 500 at a time, until in closes (after a last
// post) or ctx ends. A failed post is retried on the next tick; while posts keep failing only the
// newest 10k are kept.
func batches[T any](ctx context.Context, in <-chan T, post func([]T) bool) {
	var batch []T
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if !post(batch) {
			if len(batch) > 10000 {
				batch = append(batch[:0], batch[len(batch)-10000:]...)
			}
			return
		}
		batch = batch[:0]
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case l, ok := <-in:
			if !ok {
				flush()
				return
			}
			if batch = append(batch, l); len(batch) >= 500 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			return
		}
	}
}

// vlInsert writes batch to VictoriaLogs as JSON lines, with streamFields as its stream fields.
func vlInsert[T any](ctx context.Context, hc *http.Client, vl, streamFields string, batch []T) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, l := range batch {
		if err := enc.Encode(l); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		vl+"/insert/jsonline?_stream_fields="+streamFields, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("victorialogs: %s: %s", resp.Status, b)
	}
	return nil
}

// resumeAfter is the newest stored time of the streams filter selects (zero: none), so a restarted
// shipper resumes after it. Not knowing it would ship everything again: it waits for the store.
func resumeAfter(ctx context.Context, hc *http.Client, vl, filter string, errs prometheus.Counter, log interface{ Error(error, string, ...any) }, kv ...any) time.Time {
	t, err := vlNewest(ctx, hc, vl, filter)
	for err != nil && ctx.Err() == nil {
		log.Error(err, "logs store: where to resume", kv...)
		errs.Inc()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		t, err = vlNewest(ctx, hc, vl, filter)
	}
	return t
}

func vlNewest(ctx context.Context, hc *http.Client, vl, filter string) (time.Time, error) {
	q := url.Values{"query": {filter + " | stats max(_time) as t"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vl+"/select/logsql/query", strings.NewReader(q.Encode()))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("victorialogs: %s", resp.Status)
	}
	var row struct{ T string }
	if err := json.NewDecoder(resp.Body).Decode(&row); err != nil && err != io.EOF {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, row.T)
	return t, nil
}

// eventShipper keeps tenants' Kubernetes events, which their API servers drop after an hour, in
// VictoriaLogs for its retention period: it watches every tenant API server's events.k8s.io
// Events (all namespaces, as the tenant's admin) and writes each new or updated Event as one line
// with stream fields ctrlplane_tenant and ctrlplane_source="events". Tenants query them through
// /platform/logs. After a restart each tenant resumes after its newest stored event.
type eventShipper struct {
	client.Reader // Tenants and their admin kubeconfigs (Secret <tenant>-tenant-pki)
	platformNS    string
	vl            string // VictoriaLogs base URL
	http          *http.Client
	// config reaches a tenant's API server with its admin kubeconfig.
	config  func(kubeconfig []byte, tenant string) (*rest.Config, error)
	lines   chan eventLine
	running map[string]tenantWatch // tenant name -> its informer
}

type tenantWatch struct {
	kubeconfig string // restarted when it changes (re-issued admin cert)
	stop       context.CancelFunc
}

// inClusterConfig reaches the tenant API server through its Service (NetworkPolicy
// platform-to-apiserver), not the public endpoint in its kubeconfig; see snapshotDB.
func inClusterConfig(kubeconfig []byte, tenant string) (*rest.Config, error) {
	cfg, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err == nil {
		cfg.Host = fmt.Sprintf("https://apiserver.tenant-%s.svc:%d", tenant, apiserverPort)
	}
	return cfg, err
}

func (s *eventShipper) Start(ctx context.Context) error {
	s.running, s.lines = map[string]tenantWatch{}, make(chan eventLine, 1000)
	go s.ship(ctx)
	for {
		s.sync(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
		}
	}
}

// sync starts an informer for each tenant with an admin kubeconfig and stops those of tenants
// that are gone.
func (s *eventShipper) sync(ctx context.Context) {
	log := ctrl.Log.WithName("eventship")
	var tenants platformv1alpha1.TenantList
	if err := s.List(ctx, &tenants); err != nil {
		log.Error(err, "list tenants")
		return
	}
	want := map[string]string{}
	for _, t := range tenants.Items {
		sec := &corev1.Secret{}
		if t.DeletionTimestamp == nil && s.Get(ctx, client.ObjectKey{Namespace: s.platformNS, Name: t.Name + "-tenant-pki"}, sec) == nil &&
			len(sec.Data["admin.kubeconfig"]) > 0 {
			want[t.Name] = string(sec.Data["admin.kubeconfig"])
		}
	}
	for name, w := range s.running {
		if want[name] != w.kubeconfig {
			w.stop()
			delete(s.running, name)
		}
	}
	for name, kc := range want {
		if _, ok := s.running[name]; ok {
			continue
		}
		cfg, err := s.config([]byte(kc), name)
		if err != nil {
			log.Error(err, "tenant API server", "tenant", name)
			continue
		}
		wctx, stop := context.WithCancel(ctx)
		s.running[name] = tenantWatch{kubeconfig: kc, stop: stop}
		go s.watch(wctx, "tenant-"+name, cfg)
	}
}

// watch sends ns's events newer than its newest stored one to s.lines until ctx ends.
func (s *eventShipper) watch(ctx context.Context, ns string, cfg *rest.Config) {
	log := ctrl.Log.WithName("eventship").WithValues("tenant", ns)
	since := resumeAfter(ctx, s.http, s.vl, fmt.Sprintf(`{ctrlplane_tenant=%q,ctrlplane_source="events"}`, ns), eventshipErrors, log)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil || ctx.Err() != nil {
		return
	}
	send := func(obj any) {
		if e, ok := obj.(*eventsv1.Event); ok {
			if l := newEventLine(ns, e); l.Time.After(since) {
				select {
				case s.lines <- l:
				case <-ctx.Done():
				}
			}
		}
	}
	f := informers.NewSharedInformerFactory(cs, 0)
	_, _ = f.Events().V1().Events().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: send,
		UpdateFunc: func(old, obj any) { // a re-list repeats unchanged objects
			if old.(*eventsv1.Event).ResourceVersion != obj.(*eventsv1.Event).ResourceVersion {
				send(obj)
			}
		},
	})
	f.Start(ctx.Done())
	<-ctx.Done()
	f.Shutdown()
}

func (s *eventShipper) ship(ctx context.Context) {
	batches(ctx, s.lines, func(b []eventLine) bool {
		if err := vlInsert(ctx, s.http, s.vl, "ctrlplane_tenant,ctrlplane_source", b); err != nil {
			ctrl.Log.WithName("eventship").Error(err, "ship events")
			eventshipErrors.Inc()
			return false
		}
		return true
	})
}

type eventLine struct {
	Msg                 string    `json:"_msg"`
	Time                time.Time `json:"_time"`
	Tenant              string    `json:"ctrlplane_tenant"`
	Source              string    `json:"ctrlplane_source"`
	Type                string    `json:"type"`
	Reason              string    `json:"reason"`
	Action              string    `json:"action,omitempty"`
	Kind                string    `json:"regarding_kind"`
	Namespace           string    `json:"regarding_namespace,omitempty"`
	Name                string    `json:"regarding_name"`
	ReportingController string    `json:"reporting_controller,omitempty"`
	Count               int32     `json:"count"`
}

func newEventLine(ns string, e *eventsv1.Event) eventLine {
	return eventLine{Msg: cmp.Or(e.Note, e.Reason), Time: lastSeen(e), Tenant: ns, Source: "events",
		Type: e.Type, Reason: e.Reason, Action: e.Action,
		Kind: e.Regarding.Kind, Namespace: e.Regarding.Namespace, Name: e.Regarding.Name,
		ReportingController: cmp.Or(e.ReportingController, e.DeprecatedSource.Component), Count: eventCount(e)}
}

// lastSeen is when e last happened.
func lastSeen(e *eventsv1.Event) time.Time {
	switch {
	case e.Series != nil:
		return e.Series.LastObservedTime.Time
	case !e.DeprecatedLastTimestamp.IsZero():
		return e.DeprecatedLastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

// eventCount is how often e happened.
func eventCount(e *eventsv1.Event) int32 {
	if e.Series != nil {
		return e.Series.Count
	}
	return max(e.DeprecatedCount, 1)
}
