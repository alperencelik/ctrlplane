package main

import "testing"

// Service references resolve into the tenant's host namespace only.
func TestTenantServices(t *testing.T) {
	s := tenantServices{tenantNS: "acme", hostNS: "tenant-acme"}
	if u, err := s.ResolveEndpoint("acme", "ctrl-c-webhook", 443); err != nil || u.String() != "https://ctrl-c-webhook.tenant-acme.svc:443" {
		t.Errorf("got %v, %v", u, err)
	}
	for _, ref := range [][2]string{{"default", "kubernetes"}, {"platform-system", "platform"}, {"acme", "x.platform-system"}} {
		if u, err := s.ResolveEndpoint(ref[0], ref[1], 443); err == nil {
			t.Errorf("%s/%s resolved to %v", ref[0], ref[1], u)
		}
	}
}
