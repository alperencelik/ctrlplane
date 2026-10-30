package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
)

// Kinds of deploy lines. The site marks all but deployBaseline on the metrics charts.
const (
	deployBaseline = "baseline" // first seen long after it was created: not a change, only what later ones compare to
	deployDeployed = "deployed"
	deployChanged  = "changed" // what the customer sets: image, args, env, limits, probes
	deployRestart  = "restarted"
	deployStopped  = "stopped"
	deployStarted  = "started"
	deployRemoved  = "removed"
	deployPlatform = "platform" // a rollout with none of the above: the tunnel, a renewed cert, a platform upgrade
)

// A controller first seen when its Deployment is older than this was already there.
const deployBaselineAge = 10 * time.Minute

// platformEnvNames are the env vars controllerDeployment sets itself: a tunnel changing them is
// the platform's rollout, not a change to the customer's env.
var platformEnvNames = []string{"KUBECONFIG", "WATCH_NAMESPACE", "POD_NAMESPACE", "HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}

// deployShipper keeps a history of what ran, for the metrics charts to mark: it watches the
// controllers' Deployments and writes each change as one line to VictoriaLogs, with stream fields
// ctrlplane_tenant and ctrlplane_source="deploys". Tenants query them through /platform/logs.
// The Deployment, unlike the Tenant, also shows what the platform changed and what accounts'
// limits left of the spec. Each line stores what it saw, so a restarted shipper picks up from
// there and anything that happened meanwhile becomes a line too.
type deployShipper struct {
	cs    kubernetes.Interface
	vl    string // VictoriaLogs base URL
	http  *http.Client
	lines chan deployLine
	last  map[string]deploySnapshot // <namespace>/<controller> -> what its newest line recorded
}

func (s *deployShipper) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("deployship")
	s.lines = make(chan deployLine, 1000)
	go s.ship(ctx)
	var err error
	// Not knowing what's stored would record every controller as new: it waits for the store.
	for s.last, err = s.stored(ctx); err != nil && ctx.Err() == nil; s.last, err = s.stored(ctx) {
		log.Error(err, "logs store: where to resume")
		deployshipErrors.Inc()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	f := informers.NewSharedInformerFactoryWithOptions(s.cs, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = labelController }))
	send := func(l *deployLine) {
		if l != nil {
			select {
			case s.lines <- *l:
			case <-ctx.Done():
			}
		}
	}
	observe := func(obj any) {
		if d, ok := obj.(*appsv1.Deployment); ok {
			send(s.observe(d, time.Now()))
		}
	}
	_, _ = f.Apps().V1().Deployments().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: observe, UpdateFunc: func(_, o any) { observe(o) },
		DeleteFunc: func(o any) {
			if t, ok := o.(cache.DeletedFinalStateUnknown); ok {
				o = t.Obj
			}
			if d, ok := o.(*appsv1.Deployment); ok {
				send(s.removed(d, time.Now()))
			}
		},
	})
	f.Start(ctx.Done())
	<-ctx.Done()
	return nil
}

// observe is the line for d, if it changed since the last one. A change waits until the deployment
// controller has seen it: until then the revision is the old one, so it would look like a second,
// platform rollout right after.
func (s *deployShipper) observe(d *appsv1.Deployment, now time.Time) *deployLine {
	if !strings.HasPrefix(d.Namespace, "tenant-") || d.Status.ObservedGeneration < d.Generation {
		return nil
	}
	cur, ok := snapshotOf(d)
	if !ok {
		return nil
	}
	controller, key := d.Labels[labelController], d.Namespace+"/"+d.Labels[labelController]
	kind, msg := deployBaseline, "Baseline"
	if old, ok := s.last[key]; ok {
		kind, msg = cur.since(old)
	} else if now.Sub(d.CreationTimestamp.Time) < deployBaselineAge {
		kind, msg = deployDeployed, "Deployed "+cur.Image
	}
	if kind == "" {
		return nil
	}
	s.last[key] = cur
	b, err := json.Marshal(cur)
	if err != nil { // strings and a number
		return nil
	}
	return &deployLine{Msg: msg, Time: now, Tenant: d.Namespace, Source: "deploys", Controller: controller, Kind: kind, Snapshot: string(b)}
}

func (s *deployShipper) removed(d *appsv1.Deployment, now time.Time) *deployLine {
	controller, key := d.Labels[labelController], d.Namespace+"/"+d.Labels[labelController]
	if _, ok := s.last[key]; !ok {
		return nil
	}
	delete(s.last, key)
	return &deployLine{Msg: "Removed", Time: now, Tenant: d.Namespace, Source: "deploys", Controller: controller, Kind: deployRemoved}
}

func (s *deployShipper) ship(ctx context.Context) {
	batches(ctx, s.lines, func(b []deployLine) bool {
		if err := vlInsert(ctx, s.http, s.vl, "ctrlplane_tenant,ctrlplane_source", b); err != nil {
			ctrl.Log.WithName("deployship").Error(err, "ship deploys")
			deployshipErrors.Inc()
			return false
		}
		return true
	})
}

// stored is what each controller's newest line recorded; removed controllers have none.
func (s *deployShipper) stored(ctx context.Context) (map[string]deploySnapshot, error) {
	q := url.Values{"query": {`{ctrlplane_source="deploys"} | last 1 by (_time) partition by (ctrlplane_tenant, controller)`}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.vl+"/select/logsql/query", strings.NewReader(q.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victorialogs: %s", resp.Status)
	}
	last := map[string]deploySnapshot{}
	for dec := json.NewDecoder(resp.Body); ; {
		var l deployLine
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			return last, nil
		} else if err != nil {
			return nil, err
		}
		if l.Kind == deployRemoved {
			continue
		}
		var snap deploySnapshot
		if err := json.Unmarshal([]byte(l.Snapshot), &snap); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", l.Tenant, l.Controller, err)
		}
		last[l.Tenant+"/"+l.Controller] = snap
	}
}

type deployLine struct {
	Msg        string    `json:"_msg"`
	Time       time.Time `json:"_time"`
	Tenant     string    `json:"ctrlplane_tenant"`
	Source     string    `json:"ctrlplane_source"`
	Controller string    `json:"controller"` // not the logs' ctrlplane_controller: a log search stays logs only
	Kind       string    `json:"kind"`
	Snapshot   string    `json:"snapshot,omitempty"` // a deploySnapshot
}

// deploySnapshot is what a line compares to. Env values and args are hashed: they can hold
// secrets, which shouldn't outlive their rotation in the logs store.
type deploySnapshot struct {
	Image    string            `json:"image"`
	Args     string            `json:"args,omitempty"`
	Env      map[string]string `json:"env,omitempty"` // name -> hash of its value
	CPU      string            `json:"cpu,omitempty"` // limits
	Memory   string            `json:"memory,omitempty"`
	Probes   string            `json:"probes,omitempty"`
	Replicas int32             `json:"replicas"`
	Restart  string            `json:"restart,omitempty"` // kubectl.kubernetes.io/restartedAt
	Revision string            `json:"revision,omitempty"`
}

func deployHash(v any) string {
	b, _ := json.Marshal(v) // API types
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// snapshotOf reads d's controller container; false if it has none.
func snapshotOf(d *appsv1.Deployment) (deploySnapshot, bool) {
	pod := d.Spec.Template.Spec
	i := slices.IndexFunc(pod.Containers, func(c corev1.Container) bool { return c.Name == "controller" })
	if i < 0 {
		return deploySnapshot{}, false
	}
	c := pod.Containers[i]
	s := deploySnapshot{Image: c.Image, Replicas: ptr.Deref(d.Spec.Replicas, 1),
		Restart:  d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"],
		Revision: d.Annotations["deployment.kubernetes.io/revision"]}
	if len(c.Args) > 0 {
		s.Args = deployHash(c.Args)
	}
	for _, e := range c.Env {
		if !slices.Contains(platformEnvNames, e.Name) {
			if s.Env == nil {
				s.Env = map[string]string{}
			}
			s.Env[e.Name] = deployHash(e.Value)
		}
	}
	if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		s.CPU = q.String()
	}
	if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
		s.Memory = q.String()
	}
	if c.LivenessProbe != nil || c.ReadinessProbe != nil || c.StartupProbe != nil {
		s.Probes = deployHash([]*corev1.Probe{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe})
	}
	return s, true
}

// since says what's new in s compared to old: its kind and message, or no kind if nothing is.
func (s deploySnapshot) since(old deploySnapshot) (kind, msg string) {
	var changes []string
	change := func(name, from, to string) {
		if from != to {
			changes = append(changes, fmt.Sprintf("%s %s → %s", name, cmpNone(from), cmpNone(to)))
		}
	}
	change("image", old.Image, s.Image)
	change("CPU limit", old.CPU, s.CPU)
	change("memory limit", old.Memory, s.Memory)
	if old.Args != s.Args {
		changes = append(changes, "args changed")
	}
	if env := envChanges(old.Env, s.Env); env != "" {
		changes = append(changes, "env "+env)
	}
	if old.Probes != s.Probes {
		changes = append(changes, "probes changed")
	}
	switch {
	case len(changes) > 0:
		return deployChanged, strings.Join(changes, "; ")
	case old.Replicas > 0 && s.Replicas == 0:
		return deployStopped, "Stopped"
	case old.Replicas == 0 && s.Replicas > 0:
		return deployStarted, "Started"
	case old.Restart != s.Restart:
		return deployRestart, "Restarted"
	case old.Revision != s.Revision:
		return deployPlatform, "Rolled out by the platform (tunnel, certificate or upgrade)"
	}
	return "", ""
}

func cmpNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

// envChanges names what changed between two sets of env vars, e.g. "A changed, B added".
func envChanges(old, cur map[string]string) string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(cur)) {
		if v, ok := old[k]; !ok {
			out = append(out, k+" added")
		} else if v != cur[k] {
			out = append(out, k+" changed")
		}
	}
	for _, k := range slices.Sorted(maps.Keys(old)) {
		if _, ok := cur[k]; !ok {
			out = append(out, k+" removed")
		}
	}
	return strings.Join(out, ", ")
}
