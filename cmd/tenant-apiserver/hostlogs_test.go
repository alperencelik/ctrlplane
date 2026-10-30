package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLogPod(t *testing.T) {
	pod := func(name string, cs corev1.ContainerStatus) corev1.Pod {
		cs.Name = "controller"
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{cs}}}
	}
	stuck := pod("stuck", corev1.ContainerStatus{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}})
	crashing := pod("crashing", corev1.ContainerStatus{RestartCount: 2, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}})
	running := pod("running", corev1.ContainerStatus{State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	done := pod("done", corev1.ContainerStatus{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}})
	pending := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pending"}}

	for name, tc := range map[string]struct {
		pods []corev1.Pod
		want string
	}{
		"newest running":             {[]corev1.Pod{running, done}, "running"},
		"skips a pod that never ran": {[]corev1.Pod{stuck, running}, "running"},
		"skips a pending pod":        {[]corev1.Pod{pending, stuck, done}, "done"},
		"keeps a crash-looping pod":  {[]corev1.Pod{crashing, running}, "crashing"},
		"nothing has run":            {[]corev1.Pod{stuck, pending}, ""},
		"no pods":                    {nil, ""},
	} {
		got := ""
		if p := logPod(tc.pods); p != nil {
			got = p.Name
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}
