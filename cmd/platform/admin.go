package main

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

// The admin area (/admin): accounts, invites, sign-up settings and every control plane.
// Only admins (ADMINS) get it; everyone else gets a 404, so it isn't advertised.

type adminUser struct {
	Name, Login, Status, Since string
	Limits                     limits
	ControlPlanes              int
	Admin                      bool
}

type adminTenant struct {
	Name, Owners, Endpoint string
	Controllers            int
}

type adminData struct {
	Users               []adminUser
	Invites             []invite
	Settings            settings
	Tenants             []adminTenant
	Pending             int
	Error, NewLink, URL string
}

func (w *web) admin(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return w.authed(func(rw http.ResponseWriter, r *http.Request, user string) {
		if !acctOf(r).Admin {
			http.NotFound(rw, r)
			return
		}
		h(rw, r, user)
	})
}

func (w *web) adminData(ctx context.Context, msg string) *adminData {
	d := &adminData{Error: msg, Settings: w.acct.settings(ctx), URL: w.url}
	tenants := &platformv1alpha1.TenantList{}
	perLogin := map[string]int{}
	if err := w.List(ctx, tenants); err != nil {
		d.Error = err.Error()
	}
	for _, t := range tenants.Items {
		d.Tenants = append(d.Tenants, adminTenant{Name: t.Name, Owners: strings.Join(t.Spec.Owners, ", "),
			Endpoint: t.Status.Endpoint, Controllers: len(t.Spec.Controllers)})
		for _, o := range t.Spec.Owners {
			perLogin[o]++
		}
	}
	users := &platformv1alpha1.UserList{}
	if err := w.List(ctx, users); err != nil {
		d.Error = err.Error()
	}
	for _, u := range users.Items {
		a := accountOf(&u)
		d.Users = append(d.Users, adminUser{Name: u.GetName(), Login: a.Login, Status: a.Status, Limits: a.Limits,
			Since: u.GetCreationTimestamp().Format("Jan 2, 2006"), ControlPlanes: perLogin[a.Login], Admin: slices.Contains(w.acct.admins, a.Login)})
		if a.Status == statusPending {
			d.Pending++
		}
	}
	// Pending first (they're waiting on you), then by login.
	slices.SortFunc(d.Users, func(a, b adminUser) int {
		if (a.Status == statusPending) != (b.Status == statusPending) {
			if a.Status == statusPending {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Login, b.Login)
	})
	d.Invites, _ = w.acct.invites(ctx)
	return d
}

func (w *web) adminPage(rw http.ResponseWriter, r *http.Request, user string) {
	w.render(rw, "page", pageData{User: user, Admin: true, AdminData: w.adminData(r.Context(), "")})
}

// limitsFrom reads prefix-cp, prefix-controllers, prefix-cpu, prefix-memory and prefix-tunnel
// from the form.
func limitsFrom(r *http.Request, prefix string) (limits, error) {
	cp, err := strconv.Atoi(strings.TrimSpace(r.FormValue(prefix + "cp")))
	if err != nil {
		return limits{}, err
	}
	ctrls, err := strconv.Atoi(strings.TrimSpace(r.FormValue(prefix + "controllers")))
	if err != nil {
		return limits{}, err
	}
	l := limits{ControlPlanes: cp, Controllers: ctrls, CPU: strings.TrimSpace(r.FormValue(prefix + "cpu")),
		Memory: strings.TrimSpace(r.FormValue(prefix + "memory")), Tunnel: r.FormValue(prefix+"tunnel") == "on"}
	return l, validLimits(l)
}

// adminUser changes one account: approve, suspend, activate, limits, delete.
func (w *web) adminUser(rw http.ResponseWriter, r *http.Request, user string) {
	ctx := r.Context()
	u := &platformv1alpha1.User{}
	msg := ""
	if err := w.Get(ctx, client.ObjectKey{Name: r.PathValue("name")}, u); err != nil {
		msg = err.Error()
	} else {
		a := accountOf(u)
		switch r.FormValue("action") {
		case "approve", "activate":
			msg = errText(w.acct.putUser(ctx, a.Login, statusActive, a.Limits))
		case "suspend":
			if a.Login == user {
				msg = "you can't suspend yourself"
			} else {
				msg = errText(w.acct.putUser(ctx, a.Login, statusSuspended, a.Limits))
			}
		case "limits":
			l, err := limitsFrom(r, "")
			if err == nil {
				err = w.acct.putUser(ctx, a.Login, a.Status, l)
			}
			msg = errText(err)
		case "delete": // the account only; their control planes stay (delete those separately)
			msg = errText(client.IgnoreNotFound(w.Delete(ctx, u)))
		}
	}
	done := map[string]string{"approve": "Approved", "activate": "Activated", "suspend": "Suspended", "limits": "Saved the limits of", "delete": "Deleted the account of"}
	toast(rw, msg, done[r.FormValue("action")]+" "+r.PathValue("name"))
	w.render(rw, "admin-users", w.adminData(ctx, msg))
}

func (w *web) adminInvite(rw http.ResponseWriter, r *http.Request, user string) {
	ctx := r.Context()
	d := &adminData{}
	l, err := limitsFrom(r, "")
	if err == nil {
		var inv invite
		if inv, err = w.acct.createInvite(ctx, strings.TrimSpace(r.FormValue("login")), l); err == nil {
			d = w.adminData(ctx, "")
			d.NewLink = w.url + "/join?code=" + inv.Code
		}
	}
	if err != nil {
		d = w.adminData(ctx, err.Error())
	}
	toast(rw, errText(err), "Invite created: copy its link below")
	w.render(rw, "admin-invites", d)
}

func (w *web) adminRevoke(rw http.ResponseWriter, r *http.Request, user string) {
	msg := errText(w.acct.deleteInvite(r.Context(), r.PathValue("name")))
	toast(rw, msg, "Invite revoked")
	w.render(rw, "admin-invites", w.adminData(r.Context(), msg))
}

func (w *web) adminSettings(rw http.ResponseWriter, r *http.Request, user string) {
	ctx := r.Context()
	s := w.acct.settings(ctx)
	self, err := limitsFrom(r, "self-")
	var inv limits
	if err == nil {
		inv, err = limitsFrom(r, "inv-")
	}
	switch mode := r.FormValue("signup"); {
	case err != nil:
	case mode != "open" && mode != "approval" && mode != "invite":
		err = errString("unknown sign-up mode")
	default:
		s.Signup, s.SelfSignup, s.Invited = mode, self, inv
		err = w.acct.saveSettings(ctx, s)
	}
	d := w.adminData(ctx, errText(err))
	if err == nil {
		d.Error = ""
	}
	toast(rw, errText(err), "Settings saved")
	w.render(rw, "admin-settings", d)
}

type errString string

func (e errString) Error() string { return string(e) }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
