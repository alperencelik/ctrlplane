package main

// Accounts: who may use the platform, and within which limits.
//   - A User object (cluster-scoped, platform.ctrlplane.run/v1alpha1) per login: its status
//     (active | pending | suspended) and limits.
//   - Platform settings (sign-up mode, default limits) in ConfigMap platform-settings.
//   - Invites as Secrets in the platform namespace: a single-use code, an optional login it's
//     for, the limits it grants, and an expiry.
// Admins come from ADMINS and are always active. The site enforces status and limits for
// everything it does; the reconciler enforces CPU/memory caps, the tunnel permission and
// suspension (a suspended owner loses API access), so they hold for Tenants edited directly.

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

const (
	statusActive    = "active"
	statusPending   = "pending"
	statusSuspended = "suspended"
	statusClosed    = "closed" // no account, and sign-up is invite-only

	settingsName = "platform-settings"
	labelInvite  = "platform.ctrlplane.run/invite"
	inviteTTL    = 7 * 24 * time.Hour
)

// limits: CPU and memory are per control plane, shared by its controllers (allocate). Also
// stored in platform-settings and invites.
type limits = platformv1alpha1.Limits

// defaultControllers is what Limits.Controllers 0 means (accounts from before it existed).
const defaultControllers = 5

func maxControllers(l limits) int { return cmp.Or(l.Controllers, defaultControllers) }

// limitsFor is what applies to a control plane with these owners: the first active owner's
// limits (the first owner's if none is active; the invite defaults with no owners, i.e. made by an
// admin with kubectl), and its active owners.
func (a *accounts) limitsFor(ctx context.Context, owners []string) (limits, []string) {
	lim := a.settings(ctx).Invited
	var active []string
	for i, o := range owners {
		acct := a.lookup(ctx, o)
		if i == 0 {
			lim = acct.Limits
		}
		if acct.Status == statusActive {
			if len(active) == 0 {
				lim = acct.Limits
			}
			active = append(active, o)
		}
	}
	return lim, active
}

// budgets: the account's CPU and memory per control plane, shared by its controllers. A resource
// without a budget ("") isn't limited.
var budgets = []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory}

func budget(l limits, name corev1.ResourceName) (resource.Quantity, bool) {
	q, err := resource.ParseQuantity(map[corev1.ResourceName]string{corev1.ResourceCPU: l.CPU, corev1.ResourceMemory: l.Memory}[name])
	return q, err == nil
}

// allocate fits controllers into the account's per-control-plane budget, in order: at most
// maxControllers, each with CPU and memory limits (its own, or an even share of the budget when
// it sets none) while their sum stays within the budget. Requests default low (10m, 32Mi) and never
// exceed the limits. It returns the controllers that run, with those resources, the names of
// those that don't, and how much of each budget they use.
func allocate(ctrls []platformv1alpha1.ControllerSpec, l limits) (run []platformv1alpha1.ControllerSpec, skipped []string, used corev1.ResourceList) {
	n := maxControllers(l)
	used = corev1.ResourceList{}
	for _, c := range ctrls {
		res := *c.Resources.DeepCopy()
		fits := len(run) < n
		for _, name := range budgets {
			b, ok := budget(l, name)
			if !ok || !fits {
				continue
			}
			if res.Limits == nil {
				res.Limits = corev1.ResourceList{}
			}
			lim, set := res.Limits[name]
			if !set || lim.Cmp(b) > 0 {
				lim = shareOf(b, n)
				if set {
					lim = b // asked for more than the whole budget: the whole budget
				}
			}
			res.Limits[name] = lim
			if res.Requests == nil {
				res.Requests = corev1.ResourceList{}
			}
			if _, ok := res.Requests[name]; !ok {
				res.Requests[name] = resource.MustParse(map[corev1.ResourceName]string{corev1.ResourceCPU: "10m", corev1.ResourceMemory: "32Mi"}[name])
			}
			if req := res.Requests[name]; req.Cmp(lim) > 0 {
				res.Requests[name] = lim
			}
			total := used[name].DeepCopy()
			total.Add(lim)
			fits = total.Cmp(b) <= 0
		}
		if !fits {
			skipped = append(skipped, c.Name)
			continue
		}
		for _, name := range budgets {
			if _, ok := budget(l, name); ok {
				total := used[name].DeepCopy()
				total.Add(res.Limits[name])
				used[name] = total
			}
		}
		c.Resources = res
		run = append(run, c)
	}
	return run, skipped, used
}

// shareOf is b split evenly n ways (rounded down to a whole MiB or millicore).
func shareOf(b resource.Quantity, n int) resource.Quantity {
	if b.Format == resource.BinarySI {
		return *resource.NewQuantity(b.Value()/int64(n)/(1<<20)*(1<<20), resource.BinarySI)
	}
	return *resource.NewMilliQuantity(b.MilliValue()/int64(n), resource.DecimalSI)
}

type settings struct {
	Signup     string `json:"signup"` // open | approval | invite
	SelfSignup limits `json:"selfSignup"`
	Invited    limits `json:"invited"` // invites' defaults, and grandfathered owners
}

type account struct {
	Login, Status string
	Admin         bool
	Limits        limits
}

func defaultSettings(signup string) settings {
	return settings{Signup: cmp.Or(signup, "approval"),
		SelfSignup: limits{ControlPlanes: 1, Controllers: 3, CPU: "500m", Memory: "512Mi"},
		Invited:    limits{ControlPlanes: 1, Controllers: 5, CPU: "1", Memory: "1Gi", Tunnel: true}}
}

// userName is the User object's name for a login (logins aren't valid object names).
func userName(login string) string {
	sum := sha256.Sum256([]byte(login))
	return "u-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))[:16]
}

// accounts reads and writes the account objects; shared by the site and the reconciler.
type accounts struct {
	client.Client
	ns            string // platform namespace: settings, invites
	admins        []string
	defaultSignup string // when platform-settings doesn't exist yet
}

func (a *accounts) settings(ctx context.Context) settings {
	s := defaultSettings(a.defaultSignup)
	cm := &corev1.ConfigMap{}
	if a.Get(ctx, client.ObjectKey{Namespace: a.ns, Name: settingsName}, cm) == nil {
		_ = json.Unmarshal([]byte(cm.Data["settings.json"]), &s)
	}
	return s
}

func (a *accounts) saveSettings(ctx context.Context, s settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: a.ns, Name: settingsName}}
	if err := a.Get(ctx, client.ObjectKeyFromObject(cm), cm); apierrors.IsNotFound(err) {
		cm.Data = map[string]string{"settings.json": string(b)}
		return a.Create(ctx, cm)
	} else if err != nil {
		return err
	}
	cm.Data = map[string]string{"settings.json": string(b)}
	return a.Update(ctx, cm)
}

func (a *accounts) user(ctx context.Context, login string) (*platformv1alpha1.User, error) {
	u := &platformv1alpha1.User{}
	return u, a.Get(ctx, client.ObjectKey{Name: userName(login)}, u)
}

func accountOf(u *platformv1alpha1.User) account {
	return account{Login: u.Spec.Login, Status: u.Spec.Status, Limits: u.Spec.Limits}
}

func (a *accounts) putUser(ctx context.Context, login, status string, l limits) error {
	spec := platformv1alpha1.UserSpec{Login: login, Status: status, Limits: l}
	u, err := a.user(ctx, login)
	if apierrors.IsNotFound(err) {
		u = &platformv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: userName(login)}, Spec: spec}
		return a.Create(ctx, u)
	} else if err != nil {
		return err
	}
	u.Spec = spec
	return a.Update(ctx, u)
}

// lookup is login's account without side effects: admins are always active; logins without a
// User fall back to the invited defaults (grandfathered owners, Tenants made with kubectl).
func (a *accounts) lookup(ctx context.Context, login string) account {
	admin := slices.Contains(a.admins, login)
	if u, err := a.user(ctx, login); err == nil {
		acct := accountOf(u)
		acct.Admin = admin
		if admin {
			acct.Status = statusActive
		}
		return acct
	}
	return account{Login: login, Status: statusActive, Admin: admin, Limits: a.settings(ctx).Invited}
}

// resolve is login's account for the site, creating it on first sign-in according to the
// sign-up mode. Logins that already own control planes are kept active (grandfathered).
func (a *accounts) resolve(ctx context.Context, login string, ownsTenants bool) (account, error) {
	u, err := a.user(ctx, login)
	switch {
	case err == nil:
		acct := accountOf(u)
		if acct.Admin = slices.Contains(a.admins, login); acct.Admin {
			acct.Status = statusActive
		}
		return acct, nil
	case !apierrors.IsNotFound(err):
		return account{}, err
	}
	s := a.settings(ctx)
	status, lim := "", s.SelfSignup
	switch {
	case slices.Contains(a.admins, login) || ownsTenants:
		status, lim = statusActive, s.Invited
	case s.Signup == "open":
		status = statusActive
	case s.Signup == "approval":
		status = statusPending
	default:
		return account{Login: login, Status: statusClosed}, nil
	}
	if err := a.putUser(ctx, login, status, lim); err != nil && !apierrors.IsAlreadyExists(err) {
		return account{}, err
	}
	return a.resolve(ctx, login, ownsTenants)
}

type invite struct {
	Name, Code, Login string
	Limits            limits
	Expires           time.Time
}

func (a *accounts) invites(ctx context.Context) ([]invite, error) {
	list := &corev1.SecretList{}
	if err := a.List(ctx, list, client.InNamespace(a.ns), client.HasLabels{labelInvite}); err != nil {
		return nil, err
	}
	var out []invite
	for _, s := range list.Items {
		inv := invite{Name: s.Name, Code: string(s.Data["code"]), Login: string(s.Data["login"])}
		_ = json.Unmarshal(s.Data["limits"], &inv.Limits)
		inv.Expires, _ = time.Parse(time.RFC3339, string(s.Data["expires"]))
		out = append(out, inv)
	}
	slices.SortFunc(out, func(x, y invite) int { return y.Expires.Compare(x.Expires) })
	return out, nil
}

func (a *accounts) createInvite(ctx context.Context, login string, l limits) (invite, error) {
	inv := invite{Code: rand.Text(), Login: login, Limits: l, Expires: time.Now().Add(inviteTTL).UTC().Truncate(time.Second)}
	b, _ := json.Marshal(l)
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: a.ns, GenerateName: "invite-", Labels: map[string]string{labelInvite: "true"}},
		Data: map[string][]byte{"code": []byte(inv.Code), "login": []byte(login), "limits": b, "expires": []byte(inv.Expires.Format(time.RFC3339))}}
	if err := a.Create(ctx, s); err != nil {
		return invite{}, err
	}
	inv.Name = s.Name
	return inv, nil
}

func (a *accounts) deleteInvite(ctx context.Context, name string) error {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: a.ns, Name: name}}
	return client.IgnoreNotFound(a.Delete(ctx, s))
}

// redeem activates login with the invite's limits and uses the invite up. A suspended account
// stays suspended: only an admin lifts that.
func (a *accounts) redeem(ctx context.Context, login, code string) error {
	invs, err := a.invites(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(invs, func(inv invite) bool { return subtle.ConstantTimeCompare([]byte(inv.Code), []byte(code)) == 1 })
	switch {
	case i < 0:
		return errors.New("this invite link isn't valid (anymore)")
	case time.Now().After(invs[i].Expires):
		return errors.New("this invite link has expired; ask for a new one")
	case invs[i].Login != "" && invs[i].Login != login:
		return fmt.Errorf("this invite is for %s, but you're signed in as %s", invs[i].Login, login)
	}
	if u, err := a.user(ctx, login); err == nil && accountOf(u).Status == statusSuspended {
		return errors.New("your account is suspended")
	}
	if err := a.putUser(ctx, login, statusActive, invs[i].Limits); err != nil {
		return err
	}
	return a.deleteInvite(ctx, invs[i].Name)
}

// validLimits checks what an admin typed.
func validLimits(l limits) error {
	if l.ControlPlanes < 0 || l.ControlPlanes > 100 {
		return errors.New("control planes: 0 to 100")
	}
	if l.Controllers < 1 || l.Controllers > 20 {
		return errors.New("controllers: 1 to 20")
	}
	for _, q := range []string{l.CPU, l.Memory} {
		if _, err := resource.ParseQuantity(q); err != nil {
			return fmt.Errorf("%q: %w", q, err)
		}
	}
	return nil
}
