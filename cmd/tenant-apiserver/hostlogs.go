package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const controllerLabel = "platform.ctrlplane.run/controller"

type controllerPod struct {
	Controller string     `json:"controller"`
	Pod        string     `json:"pod"`
	Phase      string     `json:"phase"`
	Ready      bool       `json:"ready"`
	Restarts   int32      `json:"restarts"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	LastError  string     `json:"lastTerminationReason,omitempty"`
}

// controllersHandler serves, behind the tenant API server's normal authn/authz
// (non-resource URLs, so tenant RBAC decides who may read them):
//
//	GET /platform/controllers                 -> the tenant's controller pods
//	GET /platform/controllers/<name>/logs     -> their logs (?follow&tailLines&previous&sinceSeconds&timestamps)
//
// host is a host-cluster client whose RBAC only allows reading pods and pods/log in hostNS.
func controllersHandler(host kubernetes.Interface, hostNS string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/platform/controllers"), "/"), "/")
		switch {
		case parts[0] == "":
			listControllers(w, r, host, hostNS)
		case len(parts) == 2 && parts[1] == "logs":
			streamLogs(w, r, host, hostNS, parts[0])
		default:
			http.NotFound(w, r)
		}
	})
}

func controllerPods(r *http.Request, host kubernetes.Interface, hostNS, selector string) ([]corev1.Pod, error) {
	pods, err := host.CoreV1().Pods(hostNS).List(r.Context(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	// Newest first, so logs come from the current pod during a rollout (see logPod).
	sort.Slice(pods.Items, func(i, j int) bool {
		return pods.Items[j].CreationTimestamp.Before(&pods.Items[i].CreationTimestamp)
	})
	return pods.Items, nil
}

func listControllers(w http.ResponseWriter, r *http.Request, host kubernetes.Interface, hostNS string) {
	pods, err := controllerPods(r, host, hostNS, controllerLabel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out := []controllerPod{}
	for _, p := range pods {
		c := controllerPod{Controller: p.Labels[controllerLabel], Pod: p.Name, Phase: string(p.Status.Phase)}
		for _, cs := range p.Status.ContainerStatuses {
			c.Ready, c.Restarts = cs.Ready, cs.RestartCount
			if cs.State.Running != nil {
				c.StartedAt = &cs.State.Running.StartedAt.Time
			}
			if t := cs.LastTerminationState.Terminated; t != nil {
				c.LastError = t.Reason
			}
		}
		out = append(out, c)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// logPod picks the newest pod whose controller container has ever run: one stuck before that
// (a bad image, say) has no logs, while the older pod still serving during a rollout does.
// nil if none has run yet.
func logPod(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		for _, cs := range pods[i].Status.ContainerStatuses {
			if cs.Name == "controller" && (cs.State.Running != nil || cs.State.Terminated != nil || cs.RestartCount > 0) {
				return &pods[i]
			}
		}
	}
	return nil
}

func streamLogs(w http.ResponseWriter, r *http.Request, host kubernetes.Interface, hostNS, controller string) {
	pods, err := controllerPods(r, host, hostNS, controllerLabel+"="+controller)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if len(pods) == 0 {
		http.Error(w, "no pods for controller "+strconv.Quote(controller), http.StatusNotFound)
		return
	}
	pod := logPod(pods)
	if pod == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		return // nothing has run, so there's no output yet
	}
	q := r.URL.Query()
	opts := &corev1.PodLogOptions{
		Container:  "controller",
		Follow:     q.Get("follow") == "true",
		Previous:   q.Get("previous") == "true",
		Timestamps: q.Get("timestamps") == "true",
	}
	if n, err := strconv.ParseInt(q.Get("tailLines"), 10, 64); err == nil {
		opts.TailLines = &n
	}
	if n, err := strconv.ParseInt(q.Get("sinceSeconds"), 10, 64); err == nil {
		opts.SinceSeconds = &n
	}
	logs, err := host.CoreV1().Pods(hostNS).GetLogs(pod.Name, opts).Stream(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer logs.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := logs.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				_, _ = io.WriteString(w, "\n[log stream error: "+err.Error()+"]\n")
			}
			return
		}
	}
}
