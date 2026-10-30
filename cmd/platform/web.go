package main

// The website: sign in with Dex (GitHub), then list / create / delete your tenants and
// download an OIDC kubeconfig for them. Server-rendered html/template + htmx.
//
// Session = the Dex ID token itself in an HttpOnly cookie, verified on every request.
// ponytail: no refresh; users sign in again when the ID token expires (Dex default 24h).
// CSRF: cookies are SameSite=Lax and mutations require the HX-Request header, which a
// cross-site form can't send.
// The CLI (github.com/alperencelik/ctrlplane-cli) sends its ctrlplane-cli ID token as a bearer instead, and gets JSON
// from list/create/delete (Accept: application/json).

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/duration"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	platformv1alpha1 "github.com/alperencelik/ctrlplane/api/v1alpha1"
)

const (
	sessionCookie = "session"
	inviteCookie  = "invite"
	stateCookie   = "oauth-state"
	nextCookie    = "next" // where to go after signing in (login ?next=)
	cliClientID   = "ctrlplane-cli"
)

var (
	//go:embed web.html
	webHTML    string
	pages      = template.Must(template.New("").Parse(webHTML))
	tenantName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// The Tenant schema's pattern and length for controller names (api/v1alpha1).
	controllerName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$`)
)

type web struct {
	client.Client
	apiReader  client.Reader // uncached: re-reads after a conflict must see the latest object
	acct       *accounts
	url        string // the site's own URL, for invite links
	platformNS string
	issuer     string
	issuerCA   []byte      // for the kubeconfig's oidc-login; empty = system roots
	serving    atomic.Bool // the site listens (its readiness check)
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	// The stores of tenants' logs and metrics (empty: none), to tell a name still in use there.
	logsURL, metricsURL string
}

type tenantView struct {
	Name, Endpoint, Tunnel string
	Short                  string // Name without the user's prefix (shortName)
	Controllers            int
	Quota                  quotaView
}

// quotaView is a tenant's ResourceQuota "controllers" (controllerQuota) for the site: its
// controllers of how many it may run, and the CPU and memory limits they reserve of the total.
type quotaView struct{ Controllers, CPU, Memory *meterView }

// meterView feeds a <meter>: Used of Hard as text, Value of Max (milli-units) for the bar.
type meterView struct {
	Used, Hard       string
	Value, Max, High int64
}

func newMeter(used, hard resource.Quantity) *meterView {
	return &meterView{Used: used.String(), Hard: hard.String(), Value: used.MilliValue(), Max: hard.MilliValue(), High: hard.MilliValue() * 8 / 10}
}

// quota is t's use of its owner's limits: controllers of how many, and the CPU and memory limits
// they take of the budget (allocate, as the reconciler runs them). A resource without a budget is nil.
func (w *web) quota(ctx context.Context, t *platformv1alpha1.Tenant) quotaView {
	lim, _ := w.acct.limitsFor(ctx, t.Spec.Owners)
	run, _, used := allocate(t.Spec.Controllers, lim)
	v := quotaView{Controllers: newMeter(*resource.NewQuantity(int64(len(run)), resource.DecimalSI),
		*resource.NewQuantity(int64(maxControllers(lim)), resource.DecimalSI))}
	for name, m := range map[corev1.ResourceName]**meterView{corev1.ResourceCPU: &v.CPU, corev1.ResourceMemory: &v.Memory} {
		if b, ok := budget(lim, name); ok {
			*m = newMeter(used[name], b)
		}
	}
	return v
}

// left describes what's left of t's budget for one more controller, e.g. "300m CPU and 412Mi memory".
func left(q quotaView) string {
	var parts []string
	for _, p := range []struct {
		m    *meterView
		unit string
	}{{q.CPU, "CPU"}, {q.Memory, "memory"}} {
		if p.m != nil {
			rest := resource.MustParse(p.m.Hard)
			rest.Sub(resource.MustParse(p.m.Used))
			parts = append(parts, rest.String()+" "+p.unit)
		}
	}
	return strings.Join(parts, " and ")
}

type pageData struct {
	User, Prefix, Error string
	Notice              string // account not active: why
	Flash               string // a neutral message, e.g. after redeeming an invite
	Admin               bool
	Limits              limits
	MaxControllers      int        // per control plane, from Limits
	AtLimit             bool       // no more control planes allowed
	AdminData           *adminData // set on the admin page
	Tenants             []tenantView
	Pending             bool        // some tenant has no endpoint yet: poll faster
	Tenant              *tenantData // set on a tenant's own page
}

// Initial is the signed-in user's first letter, for the avatar in the top bar.
func (d pageData) Initial() string {
	if p := namePrefix(d.User); p != "" {
		return strings.ToUpper(p[:1])
	}
	return "?"
}

// serve waits for Dex to be reachable, then serves the site until ctx is done.
func (w *web) serve(ctx context.Context, addr, clientSecret, url string) error {
	var provider *oidc.Provider
	for {
		var err error
		if provider, err = oidc.NewProvider(ctx, w.issuer); err == nil {
			break
		}
		ctrl.Log.Info("web: waiting for OIDC issuer", "issuer", w.issuer, "err", err.Error())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	// Audiences: userOf accepts both clients' tokens, as the tenant API servers do.
	w.verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	w.oauth = oauth2.Config{ClientID: "ctrlplane-web", ClientSecret: clientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: url + "/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email", "federated:id"}}

	w.url = url
	srv := &http.Server{Addr: addr, Handler: secureHeaders(w.routes()), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	w.serving.Store(true)
	ctrl.Log.Info("web: serving", "addr", addr, "url", url)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (w *web) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", w.index)
	mux.HandleFunc("GET /join", w.join)
	mux.HandleFunc("GET /admin", w.admin(w.adminPage))
	mux.HandleFunc("POST /admin/users/{name}", w.admin(w.adminUser))
	mux.HandleFunc("POST /admin/invites", w.admin(w.adminInvite))
	mux.HandleFunc("DELETE /admin/invites/{name}", w.admin(w.adminRevoke))
	mux.HandleFunc("POST /admin/settings", w.admin(w.adminSettings))
	mux.HandleFunc("GET /login", w.login)
	mux.HandleFunc("GET /callback", w.callback)
	mux.HandleFunc("POST /logout", w.logout)
	mux.HandleFunc("GET /tenants", w.authed(fragment("", w.list)))
	mux.HandleFunc("POST /tenants", w.authed(w.create))
	mux.HandleFunc("DELETE /tenants/{name}", w.authed(w.delete))
	mux.HandleFunc("GET /tenants/{name}/kubeconfig", w.authed(w.kubeconfig))
	mux.HandleFunc("GET /tenants/{name}", w.authed(w.tenantPage))
	mux.HandleFunc("GET /tenants/{name}/overview", w.authed(fragment("overview", w.overview)))
	mux.HandleFunc("GET /tenants/{name}/controllers", w.authed(fragment("controllers", w.controllers)))
	mux.HandleFunc("POST /tenants/{name}/controllers", w.authed(w.addController))
	mux.HandleFunc("DELETE /tenants/{name}/controllers/{controller}", w.authed(w.removeController))
	mux.HandleFunc("POST /tenants/{name}/controllers/{controller}/restart", w.authed(w.restartController))
	mux.HandleFunc("POST /tenants/{name}/controllers/{controller}/stop", w.authed(w.stopController(true)))
	mux.HandleFunc("POST /tenants/{name}/controllers/{controller}/start", w.authed(w.stopController(false)))
	mux.HandleFunc("GET /tenants/{name}/controllers/{controller}/logs", w.authed(fragment("controllers", w.controllerLogs)))
	mux.HandleFunc("GET /tenants/{name}/metrics/{api}", w.authed(w.metrics))
	mux.HandleFunc("GET /tenants/{name}/logs/{api}", w.authed(w.logs))
	mux.HandleFunc("GET /tenants/{name}/events", w.authed(fragment("observability", w.events)))
	mux.HandleFunc("GET /tenants/{name}/tunnel", w.authed(fragment("network", w.tunnel)))
	mux.HandleFunc("POST /tenants/{name}/tunnel", w.authed(w.setTunnel))
	mux.HandleFunc("GET /tenants/{name}/resources", w.authed(fragment("resources", w.resources)))
	mux.HandleFunc("POST /tenants/{name}/resources", w.authed(w.applyResources))
	mux.HandleFunc("DELETE /tenants/{name}/resources", w.authed(w.deleteResource))
	mux.HandleFunc("GET /tenants/{name}/crds", w.authed(fragment("api", w.crds)))
	mux.HandleFunc("POST /tenants/{name}/crds", w.authed(w.applyCRDs))
	mux.HandleFunc("DELETE /tenants/{name}/crds/{crd}", w.authed(w.deleteCRD))
	mux.HandleFunc("GET /tenants/{name}/object", w.authed(fragment("api", w.object)))
	mux.HandleFunc("POST /tenants/{name}/object", w.authed(w.saveObject))
	return mux
}

// userOf mirrors usernameExpr, so the site and the tenant API servers agree on who you are.
func (w *web) userOf(ctx context.Context, rawIDToken string) (string, error) {
	tok, err := w.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(tok.Audience, func(a string) bool { return slices.Contains(oidcClients, a) }) {
		return "", errors.New("ID token for another client")
	}
	var c struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Federated         struct {
			ConnectorID string `json:"connector_id"`
		} `json:"federated_claims"`
	}
	if err := tok.Claims(&c); err != nil {
		return "", err
	}
	name := cmp.Or(c.PreferredUsername, c.Email)
	if c.Federated.ConnectorID == "" || name == "" {
		return "", errors.New("ID token lacks federated_claims or a user name")
	}
	return c.Federated.ConnectorID + ":" + name, nil
}

// secureHeaders: HTTPS only, never framed (clickjacking the delete and admin buttons), no MIME
// sniffing, no full URLs to other sites.
func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		hd.Set("Content-Security-Policy", "frame-ancestors 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.ServeHTTP(rw, r)
	})
}

func (w *web) currentUser(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	user, _ := w.userOf(r.Context(), c.Value)
	return user
}

type acctKey struct{}

// authed lets signed-in users with an active account through (see accounts.go), with the
// account in the request's context. Signed in: the session cookie, or (the CLI) an ID token as
// "Authorization: Bearer". A cookie's mutation must come from the site (HX-Request); a bearer
// token can't be sent cross-site.
func (w *web) authed(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		user := ""
		tok, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer {
			user, _ = w.userOf(r.Context(), tok)
		} else {
			user = w.currentUser(r)
		}
		if user == "" {
			http.Error(rw, "sign in first", http.StatusUnauthorized)
			return
		}
		if !bearer && r.Method != http.MethodGet && r.Header.Get("HX-Request") != "true" {
			http.Error(rw, "missing HX-Request header", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, maxManifest) // every form, not only the manifest ones
		acct, err := w.account(r.Context(), user)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if acct.Status != statusActive {
			http.Error(rw, statusText(acct.Status), http.StatusForbidden)
			return
		}
		h(rw, r.WithContext(context.WithValue(r.Context(), acctKey{}, acct)), user)
	}
}

// fragment serves h's HTML fragment to htmx; opened in a browser (a bookmark, a copied link,
// a reload after htmx pushed nothing) it redirects to the page the fragment belongs to:
// home for "", else the tenant's page on that view.
func fragment(view string, h func(http.ResponseWriter, *http.Request, string)) func(http.ResponseWriter, *http.Request, string) {
	return func(rw http.ResponseWriter, r *http.Request, user string) {
		if r.Header.Get("HX-Request") == "true" || wantsJSON(r) {
			h(rw, r, user)
			return
		}
		to := "/"
		if view != "" {
			to = "/tenants/" + url.PathEscape(r.PathValue("name")) + "#" + view
		}
		http.Redirect(rw, r, to, http.StatusFound)
	}
}

// wantsJSON: the CLI (github.com/alperencelik/ctrlplane-cli) asks for JSON instead of the site's HTML.
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// reply answers the CLI: v, or {"error": msg} with 400 when msg is set.
func reply(rw http.ResponseWriter, msg string, v any) {
	rw.Header().Set("Content-Type", "application/json")
	if msg != "" {
		rw.WriteHeader(http.StatusBadRequest)
		v = map[string]string{"error": msg}
	}
	_ = json.NewEncoder(rw).Encode(v)
}

func acctOf(r *http.Request) account {
	a, _ := r.Context().Value(acctKey{}).(account)
	return a
}

// account resolves user's account, creating it on first sign-in (sign-up mode applies).
func (w *web) account(ctx context.Context, user string) (account, error) {
	owned, err := w.owned(ctx, user)
	if err != nil {
		return account{}, err
	}
	return w.acct.resolve(ctx, user, len(owned) > 0)
}

func statusText(status string) string {
	switch status {
	case statusPending:
		return "Your account is waiting for an admin's approval."
	case statusSuspended:
		return "Your account is suspended. Contact the platform's admins."
	case statusClosed:
		return "Sign-up is by invitation only. Ask an admin for an invite link."
	}
	return "Your account isn't active."
}

func setCookie(rw http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(rw, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (w *web) index(rw http.ResponseWriter, r *http.Request) {
	user := w.currentUser(r)
	if user == "" {
		w.render(rw, "page", pageData{})
		return
	}
	acct, err := w.account(r.Context(), user)
	if err != nil {
		w.render(rw, "page", pageData{User: user, Error: err.Error()})
		return
	}
	if acct.Status != statusActive {
		w.render(rw, "page", pageData{User: user, Notice: statusText(acct.Status)})
		return
	}
	d := w.data(r.Context(), user, "", acct)
	d.Flash = r.URL.Query().Get("msg")
	w.render(rw, "page", d)
}

// join redeems an invite link: signed in, right away; otherwise after signing in (callback).
func (w *web) join(rw http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	user := w.currentUser(r)
	if user == "" {
		setCookie(rw, inviteCookie, code, 30*time.Minute)
		http.Redirect(rw, r, "/login", http.StatusFound)
		return
	}
	w.redeemAndGoHome(rw, r, user, code)
}

func (w *web) redeemAndGoHome(rw http.ResponseWriter, r *http.Request, user, code string) {
	msg := "Welcome! Your account is active."
	if err := w.acct.redeem(r.Context(), user, code); err != nil {
		msg = err.Error()
	}
	http.Redirect(rw, r, "/?msg="+url.QueryEscape(msg), http.StatusFound)
}

func (w *web) login(rw http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) { // the CLI: where to sign in, as ctrlplane-cli (public, loopback redirects)
		reply(rw, "", map[string]string{"issuer": w.issuer, "clientID": cliClientID})
		return
	}
	state := oauth2.GenerateVerifier() // just a random string here
	setCookie(rw, stateCookie, state, 10*time.Minute)
	if next := r.URL.Query().Get("next"); localPath(next) {
		setCookie(rw, nextCookie, next, 10*time.Minute)
	}
	http.Redirect(rw, r, w.oauth.AuthCodeURL(state), http.StatusFound)
}

func (w *web) callback(rw http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(stateCookie)
	if err != nil || r.URL.Query().Get("state") != c.Value {
		http.Error(rw, "login expired, try again", http.StatusBadRequest)
		return
	}
	setCookie(rw, stateCookie, "", -1)
	tok, err := w.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(rw, "login failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idTok, err := w.verifier.Verify(r.Context(), raw)
	if err != nil {
		http.Error(rw, "login failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	setCookie(rw, sessionCookie, raw, time.Until(idTok.Expiry))
	if c, err := r.Cookie(inviteCookie); err == nil && c.Value != "" {
		setCookie(rw, inviteCookie, "", -1)
		if user, err := w.userOf(r.Context(), raw); err == nil {
			w.redeemAndGoHome(rw, r, user, c.Value)
			return
		}
	}
	next := "/"
	if c, err := r.Cookie(nextCookie); err == nil && localPath(c.Value) {
		setCookie(rw, nextCookie, "", -1)
		next = c.Value
	}
	http.Redirect(rw, r, next, http.StatusFound)
}

// localPath: a path on this site, never another host (//evil.example, /\evil.example).
func localPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

// toast has the page show a short result (the "toast" listener in web.html, through htmx's
// HX-Trigger header): errMsg when set, else okMsg. Call it before render, which sends the headers.
// On success it also fires the events in also (e.g. "objects-changed", for lists to reload).
func toast(rw http.ResponseWriter, errMsg, okMsg string, also ...string) {
	t := map[string]any{"text": okMsg, "ok": true}
	if errMsg != "" {
		t = map[string]any{"text": errMsg, "ok": false}
	}
	if t["text"] == "" {
		return
	}
	events := map[string]any{"toast": t}
	if errMsg == "" {
		for _, e := range also {
			events[e] = true
		}
	}
	b, _ := json.Marshal(events)
	// Header values are bytes the browser reads as Latin-1: send non-ASCII as JSON \u escapes.
	var sb strings.Builder
	for _, c := range string(b) {
		if c < utf8.RuneSelf {
			sb.WriteRune(c)
			continue
		}
		for _, u := range utf16.Encode([]rune{c}) {
			fmt.Fprintf(&sb, `\u%04x`, u)
		}
	}
	rw.Header().Set("HX-Trigger", sb.String())
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func (w *web) logout(rw http.ResponseWriter, r *http.Request) {
	setCookie(rw, sessionCookie, "", -1)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *web) list(rw http.ResponseWriter, r *http.Request, user string) {
	d := w.data(r.Context(), user, "", acctOf(r))
	if wantsJSON(r) {
		type cp struct {
			Name     string `json:"name"`
			Status   string `json:"status"`
			Endpoint string `json:"endpoint"`
		}
		cps := []cp{}
		for _, t := range d.Tenants {
			status := "Starting" // as the site shows it
			if t.Endpoint != "" {
				status = "Ready"
			}
			cps = append(cps, cp{t.Name, status, t.Endpoint})
		}
		reply(rw, d.Error, map[string]any{"prefix": d.Prefix, "controlPlanes": cps})
		return
	}
	w.render(rw, "home", d)
}

func (w *web) create(rw http.ResponseWriter, r *http.Request, user string) {
	name := namePrefix(user) + "-" + strings.TrimSpace(r.FormValue("name"))
	msg := ""
	switch owned, err := w.owned(r.Context(), user); {
	case err != nil:
		msg = err.Error()
	case len(owned) >= acctOf(r).Limits.ControlPlanes:
		msg = fmt.Sprintf("limit reached: your account allows %d control planes", acctOf(r).Limits.ControlPlanes)
	case !tenantName.MatchString(name) || len(name) > 50:
		msg = "name: lowercase letters, digits and '-', at most 50 characters with your prefix"
	default:
		if msg = w.nameInUse(r.Context(), name); msg != "" {
			break
		}
		t := &platformv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: platformv1alpha1.TenantSpec{Owners: []string{user}}}
		if err := w.Create(r.Context(), t); apierrors.IsAlreadyExists(err) {
			msg = name + " is taken"
		} else if err != nil {
			msg = err.Error()
		} else if msg = w.overLimit(r.Context(), t, user, acctOf(r).Limits.ControlPlanes); msg != "" {
			_ = w.deleteTenant(r.Context(), t)
		}
	}
	if wantsJSON(r) {
		reply(rw, msg, map[string]string{"name": name})
		return
	}
	toast(rw, msg, "Creating "+name+": it's ready in about a minute")
	w.render(rw, "home", w.data(r.Context(), user, msg, acctOf(r)))
}

func (w *web) delete(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	msg := errText(w.deleteTenant(r.Context(), t))
	if wantsJSON(r) {
		reply(rw, msg, map[string]string{"name": t.Name})
		return
	}
	toast(rw, msg, "Deleting "+t.GetName())
	w.render(rw, "home", w.data(r.Context(), user, msg, acctOf(r)))
}

// deleteTenant deletes t with the confirmation annotation the admission policy requires (the
// owner confirmed in the site).
func (w *web) deleteTenant(ctx context.Context, t *platformv1alpha1.Tenant) error {
	patch := client.MergeFrom(t.DeepCopy())
	metav1.SetMetaDataAnnotation(&t.ObjectMeta, confirmDeleteAnno, t.Name)
	if err := w.Patch(ctx, t, patch); client.IgnoreNotFound(err) != nil {
		return err
	}
	return client.IgnoreNotFound(w.Delete(ctx, t))
}

// overLimit, after t was created, checks the limit again against the API server itself: the
// check before creating reads a cache, which concurrent requests (or two replicas) outrun. Of
// the user's control planes, the oldest `limit` stay; t, if newer, is over.
func (w *web) overLimit(ctx context.Context, t *platformv1alpha1.Tenant, user string, limit int) string {
	list := &platformv1alpha1.TenantList{}
	if err := w.apiReader.List(ctx, list); err != nil {
		return err.Error()
	}
	owned := slices.DeleteFunc(list.Items, func(o platformv1alpha1.Tenant) bool {
		return !slices.Contains(o.Spec.Owners, user) || o.DeletionTimestamp != nil
	})
	slices.SortFunc(owned, func(a, b platformv1alpha1.Tenant) int {
		return cmp.Or(a.CreationTimestamp.Compare(b.CreationTimestamp.Time), strings.Compare(a.Name, b.Name))
	})
	if i := slices.IndexFunc(owned, func(o platformv1alpha1.Tenant) bool { return o.UID == t.UID }); i >= limit {
		return fmt.Sprintf("limit reached: your account allows %d control planes", limit)
	}
	return ""
}

// nameInUse says why name can't be used yet: a deleted control plane of that name still has
// logs, events or metrics kept, which are keyed by its namespace, so a new one would see them.
// They're kept for their retention period (15 days by default).
// ponytail: one query per store on each create; tenant IDs in the stores' labels would let
// names be reused at once.
func (w *web) nameInUse(ctx context.Context, name string) string {
	if err := w.apiReader.Get(ctx, client.ObjectKey{Name: name}, &platformv1alpha1.Tenant{}); err == nil {
		return name + " is taken"
	}
	ns := "tenant-" + name
	hc := &http.Client{Timeout: 10 * time.Second}
	get := func(u string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s: %s", u, resp.Status)
		}
		return string(b), err
	}
	used := false
	if w.logsURL != "" { // controller logs and events
		out, err := get(w.logsURL + "/select/logsql/query?" + url.Values{"query": {fmt.Sprintf(`{ctrlplane_tenant=%q} | limit 1`, ns)}}.Encode())
		if err != nil {
			ctrl.Log.Error(err, "web: is the name in use", "tenant", name)
			return "can't check the name right now, try again in a minute"
		}
		used = strings.TrimSpace(out) != ""
	}
	if w.metricsURL != "" && !used {
		out, err := get(w.metricsURL + "/api/v1/series?" + url.Values{"match[]": {fmt.Sprintf(`{ctrlplane_tenant=%q}`, ns)},
			"start": {strconv.FormatInt(time.Now().Add(-90*24*time.Hour).Unix(), 10)}}.Encode())
		var res struct{ Data []json.RawMessage }
		if err == nil {
			err = json.Unmarshal([]byte(out), &res)
		}
		if err != nil {
			ctrl.Log.Error(err, "web: is the name in use", "tenant", name)
			return "can't check the name right now, try again in a minute"
		}
		used = len(res.Data) > 0
	}
	if used {
		return name + " was used by a control plane deleted recently, whose logs and metrics are still kept: choose another name"
	}
	return ""
}

// kubeconfig: the tenant's public endpoint + CA, authenticating with kubelogin (kubectl oidc-login).
func (w *web) kubeconfig(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	endpoint := t.Status.Endpoint
	pkiSecret := &corev1.Secret{}
	if err := w.Get(r.Context(), client.ObjectKey{Namespace: w.platformNS, Name: t.GetName() + "-tenant-pki"}, pkiSecret); err != nil || endpoint == "" {
		http.Error(rw, "tenant is still provisioning", http.StatusConflict)
		return
	}
	args := []string{"oidc-login", "get-token", "--oidc-issuer-url=" + w.issuer, "--oidc-client-id=" + cliClientID,
		"--oidc-extra-scope=email", "--oidc-extra-scope=profile", "--oidc-extra-scope=federated:id"}
	if len(w.issuerCA) > 0 {
		args = append(args, "--certificate-authority-data="+base64.StdEncoding.EncodeToString(w.issuerCA))
	}
	name := t.GetName()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: endpoint, CertificateAuthorityData: pkiSecret.Data["ca.crt"]}
	cfg.AuthInfos["oidc"] = &clientcmdapi.AuthInfo{Exec: &clientcmdapi.ExecConfig{
		APIVersion: "client.authentication.k8s.io/v1", Command: "kubectl", Args: args,
		InteractiveMode: clientcmdapi.IfAvailableExecInteractiveMode,
		InstallHint:     "install kubelogin: https://github.com/int128/kubelogin (kubectl krew install oidc-login)",
	}}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: "oidc", Namespace: name}
	cfg.CurrentContext = name
	b, err := clientcmd.Write(*cfg)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/yaml")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".kubeconfig"))
	_, _ = rw.Write(b)
}

// ownedTenant loads {name} and answers 404 unless user owns it (no existence leak).
func (w *web) ownedTenant(rw http.ResponseWriter, r *http.Request, user string) (*platformv1alpha1.Tenant, bool) {
	t := &platformv1alpha1.Tenant{}
	if err := w.Get(r.Context(), client.ObjectKey{Name: r.PathValue("name")}, t); err != nil || !slices.Contains(t.Spec.Owners, user) {
		http.NotFound(rw, r)
		return nil, false
	}
	return t, true
}

// ponytail: lists every Tenant and filters; index owners in a label when there are thousands.
func (w *web) owned(ctx context.Context, user string) ([]platformv1alpha1.Tenant, error) {
	list := &platformv1alpha1.TenantList{}
	if err := w.List(ctx, list); err != nil {
		return nil, err
	}
	owned := slices.DeleteFunc(list.Items, func(t platformv1alpha1.Tenant) bool { return !slices.Contains(t.Spec.Owners, user) })
	slices.SortFunc(owned, func(a, b platformv1alpha1.Tenant) int { return strings.Compare(a.Name, b.Name) }) // a stable order across polls
	return owned, nil
}

// data is the home page: the account's limits and the user's control planes with their quotas.
func (w *web) data(ctx context.Context, user, msg string, acct account) pageData {
	d := pageData{User: user, Prefix: namePrefix(user), Error: msg, Admin: acct.Admin, Limits: acct.Limits,
		MaxControllers: maxControllers(acct.Limits)}
	owned, err := w.owned(ctx, user)
	if err != nil {
		d.Error = err.Error()
	}
	d.AtLimit = len(owned) >= acct.Limits.ControlPlanes
	for _, t := range owned {
		v := tenantView{Name: t.Name, Short: shortName(user, t.Name), Endpoint: t.Status.Endpoint, Tunnel: t.Status.Tunnel, Controllers: len(t.Spec.Controllers),
			Quota: w.quota(ctx, &t)}
		d.Pending = d.Pending || v.Endpoint == ""
		d.Tenants = append(d.Tenants, v)
	}
	return d
}

func (w *web) render(rw http.ResponseWriter, name string, d any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(rw, name, d); err != nil {
		ctrl.Log.Error(err, "web: render", "template", name)
	}
}

// namePrefix scopes tenant names per user: github:Alice → alice, local:bob@example.com → bob.
func namePrefix(user string) string {
	_, name, _ := strings.Cut(user, ":")
	name, _, _ = strings.Cut(name, "@")
	return strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// shortName is how the site shows a tenant to user: alice-dev → dev for alice (her prefix is noise
// on every row). Someone else's prefix stays, so a shared control plane still says whose it is.
func shortName(user, name string) string {
	return cmp.Or(strings.TrimPrefix(name, namePrefix(user)+"-"), name)
}

// A tenant's page: its controllers (spec.controllers, run by the platform) and its CRDs
// (applied to the tenant API server as the signed-in user, so tenant RBAC decides).

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

type tenantData struct {
	Name, Endpoint, Error string
	Short                 string // Name without the user's prefix (shortName)
	Quota                 quotaView
	Left                  string // what's left of the budget, for the deploy form
	TunnelAllowed         bool   // the owner's account includes a tunnel
	Controllers           []controllerView
	CRDs                  []crdView
	Kinds                 []kindTable // the tenant's resources, one table per API type
	ResourceCount         int
	Events                []eventView
	Warnings              []eventView // the newest few, for the overview
	WarningsOnly          bool
	Starting              bool // some controller isn't ready yet: poll faster
	Tunnel                tunnelView
	Planes                []tenantView // the user's control planes, for the switcher (tenantPage)
}

type tunnelView struct {
	Type, LoginServer, URL, Connector, State string
	Forwards                                 string   // as typed in the form: name=host:port per line
	Addresses                                []string // what controllers connect to, per forward
	Targets                                  []string // host:port per forward
	Pending                                  bool     // enabled but not up (or no connector command) yet: poll faster
}

type controllerView struct {
	Name, Image, Args, Env string
	CPU, Memory, Probes    string // as set in the spec, to fill the form for an edit
	WebhookPort            string
	MetricsPort            string // set only when the spec sets metrics (else the default, :8080/metrics)
	MetricsPath            string
	MetricsHTTPS           bool
	Private                bool   // has registry credentials
	Stopped                bool   // scaled to 0 (spec.controllers[].stopped)
	Limits                 string // its CPU and memory limits as it runs, e.g. "250m CPU, 256Mi"
	State                  string // "running", or what's wrong: ImagePullBackOff, CrashLoopBackOff, ...
	Level                  string // ok | wait | bad, for the state's color
	Detail                 string // Kubernetes' message, restarts, last crash
}

type eventView struct {
	Age, Type, Object, Reason, Note, By string
	Count                               int32
}

// kindTable is one API type's objects as `kubectl get` prints them: the API server's own Table
// (NAME, the CRD's printer columns, AGE), plus NAMESPACE for namespaced types. Lists never show
// specs (they can hold credentials); opening an object does.
type kindTable struct {
	Kind, Group, Version, Resource string
	Namespaced                     bool
	Columns                        []string // after NAME
	Rows                           []kindRow
	Error                          string
}

type kindRow struct {
	Name, Namespace string
	Cells           []string
}

// objectView is one object's YAML, to read or edit (Editing: after a rejected save).
type objectView struct {
	Tenant, Kind, Name, Namespace, APIVersion string
	Group, Version, Resource                  string // what Save updates; CRD instead for API types
	CRD                                       bool
	TypeKind                                  string // a CRD's: the kind it defines
	YAML, Error                               string
	Editing                                   bool
}

type crdView struct {
	Name, Kind, Versions string
	Established          bool
}

func (w *web) tenantPage(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	// Starting (no endpoint yet): the page polls, and reloads once the tenant has one.
	if r.Header.Get("HX-Request") == "true" {
		if t.Status.Endpoint != "" {
			rw.Header().Set("HX-Refresh", "true")
		}
		return
	}
	d := w.tenantData(r.Context(), t, "")
	d.Short = shortName(user, t.Name)
	w.loadAPI(r.Context(), t, user, d)
	owned, _ := w.owned(r.Context(), user) // the switcher; without it the page still works
	for _, o := range owned {
		d.Planes = append(d.Planes, tenantView{Name: o.Name, Short: shortName(user, o.Name), Endpoint: o.Status.Endpoint})
	}
	w.render(rw, "page", pageData{User: user, Tenant: d, Admin: acctOf(r).Admin})
}

// loadAPI fills in what comes from the tenant's API server. Without an endpoint there's no API
// server to ask yet; the page says it's starting.
func (w *web) loadAPI(ctx context.Context, t *platformv1alpha1.Tenant, user string, d *tenantData) {
	if t.Status.Endpoint != "" {
		w.loadCRDs(ctx, t, user, d)
		w.loadResources(ctx, t, user, d)
		w.loadEvents(ctx, t, user, d)
	}
}

// overview refreshes the overview view. If the API server can't be asked this time, nothing
// changes (204): the view has nowhere to show why, and empty lists would read as "none".
func (w *web) overview(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := w.tenantData(r.Context(), t, "")
	w.loadAPI(r.Context(), t, user, d)
	if d.Error != "" {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	w.render(rw, "overview", d)
}

func (w *web) controllers(rw http.ResponseWriter, r *http.Request, user string) {
	if t, ok := w.ownedTenant(rw, r, user); ok {
		w.render(rw, "controllers", w.tenantData(r.Context(), t, ""))
	}
}

func (w *web) addController(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxManifest) // a deployment.yaml, below
	fromYAML := r.FormValue("source") == "yaml"
	c := platformv1alpha1.ControllerSpec{Name: strings.TrimSpace(r.FormValue("name")), Image: strings.TrimSpace(r.FormValue("image")),
		Args: lines(r.FormValue("args"))}
	for _, l := range lines(r.FormValue("env")) {
		k, v, _ := strings.Cut(l, "=")
		c.Env = append(c.Env, platformv1alpha1.EnvVar{Name: strings.TrimSpace(k), Value: v})
	}
	msg := ""
	var ignored []string // what the deployment.yaml sets that the form has no field for
	if fromYAML {        // ctrlplane deploy -f: the form, filled from the operator's Deployment (deployments.go)
		given := c
		c, ignored, msg = controllerFromManifests(rw, r)
		if given.Name != "" { // fields given as well win, as flags over the file
			c.Name = given.Name
		} else if len(c.Name) > 40 && msg == "" {
			msg = fmt.Sprintf("the Deployment's name %q is longer than 40 characters: give the controller a shorter name", c.Name)
		}
		c.Image = cmp.Or(given.Image, c.Image)
		if given.Args != nil {
			c.Args = given.Args
		}
		if given.Env != nil {
			c.Env = given.Env
		}
	}
	list := slices.Clone(t.Spec.Controllers)
	i := slices.IndexFunc(list, func(o platformv1alpha1.ControllerSpec) bool { return o.Name == c.Name })
	if i >= 0 { // same name: update it (new image, args, env), keeping its registry credentials, and limits, probes and metrics unless new ones are given
		c.ImagePullSecrets, c.Stopped = list[i].ImagePullSecrets, list[i].Stopped
		if !fromYAML { // a deployment.yaml says them all
			c.Resources = list[i].Resources
			c.LivenessProbe, c.ReadinessProbe, c.StartupProbe = list[i].LivenessProbe, list[i].ReadinessProbe, list[i].StartupProbe
			c.Metrics = list[i].Metrics
		}
	}
	if port, path, https := strings.TrimSpace(r.FormValue("metricsPort")), strings.TrimSpace(r.FormValue("metricsPath")), r.FormValue("metricsHTTPS") != ""; port != "" || path != "" || https {
		m := &platformv1alpha1.MetricsSpec{Port: 8080, Path: path}
		if port != "" {
			if p, err := strconv.ParseInt(port, 10, 32); err != nil || p < 0 || p > 65535 {
				msg = cmp.Or(msg, fmt.Sprintf("metrics port %q: a port, e.g. 8080, or 0 for none", port))
			} else {
				m.Port = int32(p)
			}
		}
		if https {
			m.Scheme = "https"
		}
		c.Metrics = m
	}
	if y := strings.TrimSpace(r.FormValue("probes")); y != "" {
		var p struct {
			LivenessProbe  *platformv1alpha1.Probe `json:"livenessProbe"`
			ReadinessProbe *platformv1alpha1.Probe `json:"readinessProbe"`
			StartupProbe   *platformv1alpha1.Probe `json:"startupProbe"`
		}
		if err := yaml.UnmarshalStrict([]byte(y), &p); err != nil {
			msg = "probes: " + err.Error()
		}
		c.LivenessProbe, c.ReadinessProbe, c.StartupProbe = p.LivenessProbe, p.ReadinessProbe, p.StartupProbe
	}
	if v := strings.TrimSpace(r.FormValue("webhookPort")); v != "" && msg == "" {
		if p, err := strconv.ParseInt(v, 10, 32); err != nil || p < 1 || p > 65535 {
			msg = fmt.Sprintf("webhook port %q: a port, e.g. 9443", v)
		} else {
			c.Webhook = &platformv1alpha1.WebhookSpec{Port: int32(p)}
		}
	}
	registryPassword := r.FormValue("registryPassword")
	if registryPassword != "" {
		c.ImagePullSecrets = []string{c.Name}
	}
	// Checked here as well as by the Tenant schema: the registry Secret is saved before the
	// Tenant, so a name the schema refuses would leave it behind.
	if !controllerName.MatchString(c.Name) && msg == "" {
		msg = fmt.Sprintf("name %q: lowercase letters, digits and '-', at most 40 characters", c.Name)
	}
	if (len(registryPassword) > 4096 || len(r.FormValue("registryUser")) > 256) && msg == "" {
		msg = "registry credentials: at most 256 characters for the username, 4096 for the password"
	}
	for name, field := range map[corev1.ResourceName]string{corev1.ResourceCPU: "cpu", corev1.ResourceMemory: "memory"} {
		v := strings.TrimSpace(r.FormValue(field))
		if v == "" || msg != "" {
			continue
		}
		q, err := resource.ParseQuantity(v)
		if err != nil || q.Sign() <= 0 {
			msg = fmt.Sprintf("%s limit %q: e.g. 250m CPU, 128Mi memory", field, v)
			break
		}
		if c.Resources.Limits == nil {
			c.Resources.Limits = corev1.ResourceList{}
		}
		c.Resources.Limits[name] = q
	}
	lim, _ := w.acct.limitsFor(r.Context(), t.Spec.Owners)
	switch {
	case msg != "":
	case i >= 0:
		list[i] = c
	case len(list) >= maxControllers(lim):
		msg = fmt.Sprintf("limit reached: %d controllers per control plane", maxControllers(lim))
	default:
		list = append(list, c)
	}
	if msg == "" {
		if _, skipped, _ := allocate(list, lim); slices.Contains(skipped, c.Name) {
			others := t.DeepCopy()
			others.Spec.Controllers = slices.DeleteFunc(slices.Clone(list), func(o platformv1alpha1.ControllerSpec) bool { return o.Name == c.Name })
			msg = fmt.Sprintf("%s doesn't fit this control plane's limits: %s left; set lower limits, or lower another controller's", c.Name, left(w.quota(r.Context(), others)))
		}
	}
	if msg == "" && registryPassword != "" {
		msg = w.saveRegistry(r.Context(), "tenant-"+t.GetName(), c.Name, c.Image, strings.TrimSpace(r.FormValue("registryUser")), registryPassword)
	}
	if msg == "" {
		t.Spec.Controllers = list
		msg = w.update(r.Context(), t)
		if msg != "" && registryPassword != "" && i < 0 { // not saved: its credentials go too
			_ = client.IgnoreNotFound(w.Delete(r.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-" + t.GetName(), Name: registrySecret(c.Name)}}))
		}
	}
	if wantsJSON(r) { // ctrlplane deploy
		reply(rw, msg, map[string]any{"name": c.Name, "updated": i >= 0, "ignored": ignored})
		return
	}
	note := ""
	if len(ignored) > 0 {
		note = ". Not used from the Deployment: " + strings.Join(ignored, ", ")
	}
	if i >= 0 {
		toast(rw, msg, "Updated "+c.Name+": rolling out"+note)
	} else {
		toast(rw, msg, "Deployed "+c.Name+": starting"+note)
	}
	w.render(rw, "controllers", w.tenantData(r.Context(), t, msg))
}

// saveRegistry stores credentials for image's registry as Secret registry-<name> in ns; like the
// Tailscale key, they're never shown again. Returns an error message.
func (w *web) saveRegistry(ctx context.Context, ns, name, image, user, password string) string {
	if user == "" {
		return "a registry username is required with the password"
	}
	host := "https://index.docker.io/v1/" // Docker Hub: images without a registry host
	if first, _, ok := strings.Cut(image, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host = first
	}
	cfg, err := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{
		"username": user, "password": password, "auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + password))}}})
	if err == nil {
		err = w.Apply(ctx, corev1ac.Secret(registrySecret(name), ns).WithType(corev1.SecretTypeDockerConfigJson).
			WithData(map[string][]byte{corev1.DockerConfigJsonKey: cfg}), fieldOwner, client.ForceOwnership)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func (w *web) removeController(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	t.Spec.Controllers = slices.DeleteFunc(t.Spec.Controllers, func(o platformv1alpha1.ControllerSpec) bool { return o.Name == r.PathValue("controller") })
	msg := w.update(r.Context(), t)
	if msg == "" { // its registry credentials, if the site saved any
		_ = client.IgnoreNotFound(w.Delete(r.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-" + t.GetName(), Name: registrySecret(r.PathValue("controller"))}}))
	}
	if wantsJSON(r) { // ctrlplane rm
		reply(rw, msg, map[string]string{"name": r.PathValue("controller")})
		return
	}
	toast(rw, msg, "Removed "+r.PathValue("controller"))
	w.render(rw, "controllers", w.tenantData(r.Context(), t, msg))
}

func (w *web) restartController(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	name := r.PathValue("controller")
	msg := "no controller " + strconv.Quote(name)
	if slices.ContainsFunc(t.Spec.Controllers, func(o platformv1alpha1.ControllerSpec) bool { return o.Name == name }) {
		msg = errText(restartDeployment(r.Context(), w.Client, "tenant-"+t.GetName(), "ctrl-"+name))
	}
	if wantsJSON(r) { // ctrlplane restart
		reply(rw, msg, map[string]string{"name": name})
		return
	}
	toast(rw, msg, "Restarting "+name)
	d := w.tenantData(r.Context(), t, msg)
	d.Starting = msg == "" // poll until the new pod is up; right after the patch, the old one still looks fine
	w.render(rw, "controllers", d)
}

// stopController scales a controller to 0 (stop) or back to 1 (start), via spec.controllers[].stopped.
func (w *web) stopController(stop bool) func(http.ResponseWriter, *http.Request, string) {
	return func(rw http.ResponseWriter, r *http.Request, user string) {
		t, ok := w.ownedTenant(rw, r, user)
		if !ok {
			return
		}
		name := r.PathValue("controller")
		msg := "no controller " + strconv.Quote(name)
		if i := slices.IndexFunc(t.Spec.Controllers, func(o platformv1alpha1.ControllerSpec) bool { return o.Name == name }); i >= 0 {
			t.Spec.Controllers[i].Stopped = stop
			msg = w.update(r.Context(), t)
		}
		if wantsJSON(r) { // ctrlplane stop / start
			reply(rw, msg, map[string]any{"name": name, "stopped": stop})
			return
		}
		toast(rw, msg, map[bool]string{true: "Stopped ", false: "Starting "}[stop]+name)
		w.render(rw, "controllers", w.tenantData(r.Context(), t, msg))
	}
}

// restartDeployment rolls a deployment's pods as `kubectl rollout restart` does. A merge patch
// under its own field manager, so the reconciler's server-side apply leaves the annotation be.
func restartDeployment(ctx context.Context, c client.Client, ns, name string) error {
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().Format(time.RFC3339))
	return c.Patch(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}},
		client.RawPatch(types.MergePatchType, []byte(patch)), client.FieldOwner("ctrlplane-web"))
}

// update stores an edited Tenant; the Tenant CRD schema validates it. Returns an error message.
// The reconciler's status writes also bump resourceVersion: on a conflict where the spec is
// unchanged (same generation), the edit is re-applied to the fresh object. A concurrent spec
// edit is still a conflict.
func (w *web) update(ctx context.Context, t *platformv1alpha1.Tenant) string {
	err := w.Update(ctx, t)
	for i := 0; i < 3 && apierrors.IsConflict(err); i++ {
		cur := &platformv1alpha1.Tenant{}
		if w.apiReader.Get(ctx, client.ObjectKeyFromObject(t), cur) != nil || cur.Generation != t.Generation {
			break
		}
		cur.Spec = t.Spec
		if err = w.Update(ctx, cur); err == nil {
			*t = *cur
		}
	}
	if err != nil {
		_ = w.Get(ctx, client.ObjectKeyFromObject(t), t) // show what's stored, not the rejected edit
		if apierrors.IsConflict(err) {
			return "the tenant changed meanwhile, try again"
		}
		return err.Error()
	}
	return ""
}

func (w *web) tenantData(ctx context.Context, t *platformv1alpha1.Tenant, msg string) *tenantData {
	d := &tenantData{Name: t.GetName(), Error: msg, Quota: w.quota(ctx, t)}
	d.Left = left(d.Quota)
	d.Endpoint = t.Status.Endpoint
	spec := t.Spec
	lim, _ := w.acct.limitsFor(ctx, spec.Owners)
	d.TunnelAllowed = lim.Tunnel
	run, _, _ := allocate(spec.Controllers, lim)
	for _, c := range spec.Controllers {
		v := controllerView{Name: c.Name, Image: c.Image, Args: strings.Join(c.Args, "\n"), State: "starting", Private: len(c.ImagePullSecrets) > 0, Stopped: c.Stopped}
		for _, e := range c.Env {
			v.Env += e.Name + "=" + e.Value + "\n"
		}
		if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
			v.CPU = q.String()
		}
		if c.Webhook != nil {
			v.WebhookPort = fmt.Sprint(cmp.Or(c.Webhook.Port, 9443))
		}
		if m := c.Metrics; m != nil {
			v.MetricsPort, v.MetricsPath, v.MetricsHTTPS = fmt.Sprint(m.Port), m.Path, m.Scheme == "https"
		}
		if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			v.Memory = q.String()
		}
		if c.LivenessProbe != nil || c.ReadinessProbe != nil || c.StartupProbe != nil {
			y, _ := yaml.Marshal(struct {
				LivenessProbe  *platformv1alpha1.Probe `json:"livenessProbe,omitempty"`
				ReadinessProbe *platformv1alpha1.Probe `json:"readinessProbe,omitempty"`
				StartupProbe   *platformv1alpha1.Probe `json:"startupProbe,omitempty"`
			}{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe})
			v.Probes = string(y)
		}
		i := slices.IndexFunc(run, func(o platformv1alpha1.ControllerSpec) bool { return o.Name == c.Name })
		if i < 0 {
			v.State, v.Level, v.Detail = "not running", "bad", "over this control plane's limits: lower its limits or another controller's"
			d.Controllers = append(d.Controllers, v)
			continue
		}
		var parts []string
		if q, ok := run[i].Resources.Limits[corev1.ResourceCPU]; ok {
			parts = append(parts, q.String()+" CPU")
		}
		if q, ok := run[i].Resources.Limits[corev1.ResourceMemory]; ok {
			parts = append(parts, q.String())
		}
		v.Limits = strings.Join(parts, ", ")
		if c.Stopped {
			v.State, v.Detail = "stopped", "scaled to 0: start it to reconcile again"
			d.Controllers = append(d.Controllers, v)
			continue
		}
		v.State, v.Level, v.Detail = w.controllerState(ctx, "tenant-"+t.GetName(), c.Name)
		d.Starting = d.Starting || v.State != "running"
		d.Controllers = append(d.Controllers, v)
	}
	if spec.Tunnel != nil {
		ns := "tenant-" + t.GetName()
		d.Tunnel = tunnelView{Type: spec.Tunnel.Type, LoginServer: spec.Tunnel.Tailscale.LoginServer, State: w.deployState(ctx, ns, "tunnel")}
		d.Tunnel.URL = t.Status.Tunnel
		for _, f := range spec.Tunnel.Forwards {
			target := net.JoinHostPort(f.Host, strconv.Itoa(int(f.Port)))
			d.Tunnel.Forwards += f.Name + "=" + target + "\n"
			d.Tunnel.Addresses = append(d.Tunnel.Addresses, fmt.Sprintf("%s:%d → %s", f.Name, f.Port, target))
			d.Tunnel.Targets = append(d.Tunnel.Targets, target)
		}
		sec := &corev1.Secret{}
		if d.Tunnel.Type == "chisel" && w.Get(ctx, client.ObjectKey{Namespace: ns, Name: "tunnel"}, sec) == nil {
			d.Tunnel.Connector = string(sec.Data["connector"])
		}
		d.Tunnel.Pending = d.Tunnel.State != "running" || d.Tunnel.Type == "chisel" && d.Tunnel.Connector == ""
	}
	return d
}

// setForwards parses "name=host:port" lines into tun.Forwards; the CRD schema validates the
// values. Returns an error message.
func setForwards(tun *platformv1alpha1.TunnelSpec, text string) string {
	for _, l := range lines(text) {
		name, target, _ := strings.Cut(l, "=")
		host, port, err := net.SplitHostPort(strings.TrimSpace(target))
		p, perr := strconv.ParseInt(port, 10, 32)
		if err != nil || perr != nil {
			return fmt.Sprintf("forward %q: want name=host:port", l)
		}
		tun.Forwards = append(tun.Forwards, platformv1alpha1.ForwardSpec{Name: strings.TrimSpace(name), Host: host, Port: int32(p)})
	}
	return ""
}

// controllerState reports what Kubernetes says about a controller's pods, not just ready or not:
// the waiting/termination reason (ImagePullBackOff, CrashLoopBackOff, OOMKilled, ...), its
// message, and restarts. A rollout whose new pod isn't up while the old one serves is described
// by updateState.
func (w *web) controllerState(ctx context.Context, ns, name string) (state, level, detail string) {
	pods := &corev1.PodList{}
	if err := w.List(ctx, pods, client.InNamespace(ns), client.MatchingLabels{labelController: name}); err != nil || len(pods.Items) == 0 {
		st := w.deployState(ctx, ns, "ctrl-"+name)
		return st, map[bool]string{true: "ok", false: "wait"}[st == "running"], ""
	}
	slices.SortFunc(pods.Items, func(a, b corev1.Pod) int { return b.CreationTimestamp.Compare(a.CreationTimestamp.Time) })
	serving := slices.ContainsFunc(pods.Items, func(p corev1.Pod) bool { return p.DeletionTimestamp == nil && podReady(p) })
	st, lvl, msg := podState(pods.Items[0])
	switch {
	case st == "running":
		return st, "ok", msg
	case serving: // still works, but needs attention
		return updateState(st, lvl, msg)
	}
	return st, lvl, msg
}

// updateState is a rollout's state while an older pod still serves, given the new pod's podState.
// A new pod that's still on its way leaves the controller "running". One that has failed isn't
// reported as running, so it stands out and the page polls until it's fixed.
func updateState(st, lvl, msg string) (state, level, detail string) {
	detail = strings.TrimSuffix(st+": "+msg, ": ")
	if lvl == "bad" {
		return "update failing", "bad", "The previous version is still serving. " + detail
	}
	return "running", "wait", "update not starting: " + detail
}

func podReady(p corev1.Pod) bool {
	return slices.ContainsFunc(p.Status.Conditions, func(c corev1.PodCondition) bool {
		return c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
	})
}

// podState is the pod's most telling state: a container's waiting/terminated reason, an
// unschedulable pod, or running (with restarts and the last crash, if any).
func podState(p corev1.Pod) (state, level, detail string) {
	bad := func(reason string) string {
		for _, r := range []string{"BackOff", "Err", "Error", "OOMKilled", "Invalid", "Unschedulable", "Failed"} {
			if strings.Contains(reason, r) {
				return "bad"
			}
		}
		return "wait"
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason != "" {
			return c.Reason, bad(c.Reason), c.Message
		}
	}
	var restarts int32
	var lastCrash string
	for _, cs := range p.Status.ContainerStatuses {
		restarts += cs.RestartCount
		if t := cs.LastTerminationState.Terminated; t != nil && lastCrash == "" {
			lastCrash = fmt.Sprintf("last exit: %s (code %d)", t.Reason, t.ExitCode)
		}
		switch {
		case cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "ContainerCreating" && cs.State.Waiting.Reason != "PodInitializing":
			return cs.State.Waiting.Reason, bad(cs.State.Waiting.Reason), strings.TrimPrefix(cs.State.Waiting.Message+suffix(restarts, lastCrash), " · ")
		case cs.State.Terminated != nil:
			return cs.State.Terminated.Reason, bad(cs.State.Terminated.Reason),
				strings.TrimSpace(fmt.Sprintf("exit code %d %s", cs.State.Terminated.ExitCode, cs.State.Terminated.Message))
		}
	}
	switch {
	case p.Status.Phase == corev1.PodRunning && podReady(p):
		return "running", "ok", strings.TrimPrefix(suffix(restarts, lastCrash), " · ")
	case p.Status.Phase == corev1.PodPending:
		return "starting", "wait", ""
	}
	return "not ready", "wait", strings.TrimPrefix(suffix(restarts, lastCrash), " · ")
}

func suffix(restarts int32, lastCrash string) string {
	if restarts == 0 {
		return ""
	}
	s := fmt.Sprintf(" · %d restarts", restarts)
	if restarts == 1 {
		s = " · 1 restart"
	}
	if lastCrash != "" {
		s += ", " + lastCrash
	}
	return s
}

func (w *web) deployState(ctx context.Context, ns, name string) string {
	dep := &appsv1.Deployment{}
	if err := w.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, dep); err != nil {
		return "starting"
	}
	if dep.Status.ObservedGeneration >= dep.Generation && dep.Status.UpdatedReplicas > 0 && dep.Status.UnavailableReplicas == 0 {
		return "running"
	}
	return "not ready"
}

func (w *web) tunnel(rw http.ResponseWriter, r *http.Request, user string) {
	if t, ok := w.ownedTenant(rw, r, user); ok {
		w.render(rw, "tunnel", w.tenantData(r.Context(), t, ""))
	}
}

// setTunnel sets spec.tunnel from the form: type "" (off), chisel, or tailscale. A Tailscale
// auth key goes to Secret tailscale-auth in the tenant namespace; it's never shown again.
func (w *web) setTunnel(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	ctx, ns := r.Context(), "tenant-"+t.GetName()
	if r.FormValue("type") != "" && !acctOf(r).Limits.Tunnel {
		w.render(rw, "tunnel", w.tenantData(ctx, t, "your account can't connect a network; ask an admin"))
		return
	}
	msg := ""
	switch r.FormValue("type") {
	case "":
		t.Spec.Tunnel = nil
	case "chisel":
		tun := &platformv1alpha1.TunnelSpec{Type: "chisel"}
		msg = setForwards(tun, r.FormValue("forwards"))
		t.Spec.Tunnel = tun
	case "tailscale":
		tun := &platformv1alpha1.TunnelSpec{Type: "tailscale"}
		msg = setForwards(tun, r.FormValue("forwards"))
		tun.Tailscale.LoginServer = strings.TrimSpace(r.FormValue("loginServer"))
		if msg != "" {
			break
		}
		if key := strings.TrimSpace(r.FormValue("authkey")); key != "" {
			if err := w.Apply(ctx, corev1ac.Secret("tailscale-auth", ns).WithData(map[string][]byte{"authkey": []byte(key)}),
				fieldOwner, client.ForceOwnership); err != nil {
				msg = err.Error()
			}
		} else if err := w.Get(ctx, client.ObjectKey{Namespace: ns, Name: "tailscale-auth"}, &corev1.Secret{}); apierrors.IsNotFound(err) {
			msg = "a Tailscale auth key is required"
		}
		t.Spec.Tunnel = tun
	default:
		msg = "unknown tunnel type"
	}
	if msg == "" {
		msg = w.update(ctx, t)
	} else {
		_ = w.Get(ctx, client.ObjectKeyFromObject(t), t) // show what's stored, not the rejected edit
	}
	if r.FormValue("type") == "" {
		toast(rw, msg, "Tunnel turned off")
	} else {
		toast(rw, msg, "Tunnel saved: controllers reconnect in a moment")
	}
	w.render(rw, "tunnel", w.tenantData(ctx, t, msg))
}

func (w *web) crds(rw http.ResponseWriter, r *http.Request, user string) {
	if t, ok := w.ownedTenant(rw, r, user); ok {
		if t.Status.Endpoint == "" { // no API server to ask yet
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		d := &tenantData{Name: t.GetName()}
		w.loadCRDs(r.Context(), t, user, d)
		w.render(rw, "crds", d)
	}
}

// applyCRDs server-side applies the CustomResourceDefinitions in the pasted, uploaded and/or linked YAML.
func (w *web) applyCRDs(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := &tenantData{Name: t.GetName()}
	applied := 0
	d.Error = func() string {
		objs, msg := readManifests(rw, r)
		if msg != "" {
			return msg
		}
		applied = len(objs)
		for _, o := range objs {
			if o.GetAPIVersion() != "apiextensions.k8s.io/v1" || o.GetKind() != "CustomResourceDefinition" {
				return fmt.Sprintf("only CustomResourceDefinitions (apiextensions.k8s.io/v1) here, got %s %q; add other objects under Resources", o.GetKind(), o.GetName())
			}
		}
		if len(objs) == 0 {
			return "no CustomResourceDefinitions found"
		}
		dc, err := w.tenantClient(r.Context(), t, user)
		if err != nil {
			return err.Error()
		}
		for _, o := range objs {
			if _, err := dc.Resource(crdGVR).Apply(r.Context(), o.GetName(), o, metav1.ApplyOptions{FieldManager: "ctrlplane-web", Force: true}); err != nil {
				return o.GetName() + ": " + err.Error()
			}
		}
		return ""
	}()
	toast(rw, d.Error, "Applied "+plural(applied, "CRD"))
	w.loadCRDs(r.Context(), t, user, d)
	w.render(rw, "crds", d)
}

// readManifests decodes the pasted (yaml), uploaded (file) and linked (url, one per line)
// manifests of a form. Returns an error message.
func readManifests(rw http.ResponseWriter, r *http.Request) ([]*unstructured.Unstructured, string) {
	r.Body = http.MaxBytesReader(rw, r.Body, maxManifest)
	var text strings.Builder
	text.WriteString(r.FormValue("yaml"))
	urls := lines(r.FormValue("url"))
	if len(urls) > maxManifestURLs {
		return nil, fmt.Sprintf("at most %d URLs at a time", maxManifestURLs)
	}
	for _, u := range urls {
		b, err := fetchManifest(r.Context(), u)
		if err != nil {
			return nil, u + ": " + err.Error()
		}
		text.WriteString("\n---\n" + b)
		if text.Len() > maxManifest {
			return nil, fmt.Sprintf("larger than %d MiB in all", maxManifest>>20)
		}
	}
	if f, _, err := r.FormFile("file"); err == nil {
		b, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
		if err != nil {
			return nil, err.Error()
		}
		text.WriteString("\n---\n" + string(b))
		if text.Len() > maxManifest {
			return nil, fmt.Sprintf("larger than %d MiB in all", maxManifest>>20)
		}
	}
	var objs []*unstructured.Unstructured
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(text.String()), 4096)
	for {
		o := &unstructured.Unstructured{}
		if err := dec.Decode(&o.Object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, "invalid YAML: " + err.Error()
		}
		if len(o.Object) != 0 {
			objs = append(objs, o)
		}
	}
	return objs, ""
}

func (w *web) deleteCRD(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := &tenantData{Name: t.GetName()}
	if dc, err := w.tenantClient(r.Context(), t, user); err != nil {
		d.Error = err.Error()
	} else if err := dc.Resource(crdGVR).Delete(r.Context(), r.PathValue("crd"), metav1.DeleteOptions{}); client.IgnoreNotFound(err) != nil {
		d.Error = err.Error()
	}
	toast(rw, d.Error, "Deleted "+r.PathValue("crd"))
	w.loadCRDs(r.Context(), t, user, d)
	w.render(rw, "crds", d)
}

func (w *web) loadCRDs(ctx context.Context, t *platformv1alpha1.Tenant, user string, d *tenantData) {
	dc, err := w.tenantClient(ctx, t, user)
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	list, err := dc.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	for _, c := range list.Items {
		v := crdView{Name: c.GetName()}
		v.Kind, _, _ = unstructured.NestedString(c.Object, "spec", "names", "kind")
		versions, _, _ := unstructured.NestedSlice(c.Object, "spec", "versions")
		for _, ver := range versions {
			if name, _ := ver.(map[string]any)["name"].(string); name != "" {
				v.Versions = strings.TrimPrefix(v.Versions+", "+name, ", ")
			}
		}
		conds, _, _ := unstructured.NestedSlice(c.Object, "status", "conditions")
		v.Established = slices.ContainsFunc(conds, func(o any) bool {
			m, _ := o.(map[string]any)
			return m["type"] == "Established" && m["status"] == "True"
		})
		d.CRDs = append(d.CRDs, v)
	}
}

func (w *web) tenantClient(ctx context.Context, t *platformv1alpha1.Tenant, user string) (dynamic.Interface, error) {
	cfg, err := w.tenantConfig(ctx, t, user)
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(cfg)
}

// tenantConfig talks to the tenant API server as user: the platform's admin credentials
// with impersonation, so the tenant's RBAC (not this site) decides what's allowed.
func (w *web) tenantConfig(ctx context.Context, t *platformv1alpha1.Tenant, user string) (*rest.Config, error) {
	s := &corev1.Secret{}
	if err := w.Get(ctx, client.ObjectKey{Namespace: w.platformNS, Name: t.GetName() + "-tenant-pki"}, s); err != nil || len(s.Data["admin.kubeconfig"]) == 0 {
		return nil, errors.New("tenant is still provisioning")
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(s.Data["admin.kubeconfig"])
	if err != nil {
		return nil, err
	}
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: []string{"system:authenticated"}}
	cfg.Timeout = 15 * time.Second
	return cfg, nil
}

// Resources: objects of the tenant's CRD types, applied and listed as the signed-in user,
// so the tenant's RBAC decides (its CRD types anywhere; built-ins only in its namespace).

func (w *web) resources(rw http.ResponseWriter, r *http.Request, user string) {
	if t, ok := w.ownedTenant(rw, r, user); ok {
		if t.Status.Endpoint == "" { // no API server to ask yet
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		d := &tenantData{Name: t.GetName()}
		w.loadResources(r.Context(), t, user, d)
		w.render(rw, "resources", d)
	}
}

// applyResources server-side applies any objects; namespaced ones without a namespace go to
// the tenant namespace.
func (w *web) applyResources(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := &tenantData{Name: t.GetName()}
	applied := 0
	d.Error = func() string {
		objs, msg := readManifests(rw, r)
		if msg != "" {
			return msg
		}
		if len(objs) == 0 {
			return "no objects found"
		}
		applied = len(objs)
		cfg, err := w.tenantConfig(r.Context(), t, user)
		if err != nil {
			return err.Error()
		}
		dc, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return err.Error()
		}
		disc, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			return err.Error()
		}
		mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disc))
		for _, o := range objs {
			gvk := o.GroupVersionKind()
			m, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if err != nil {
				return fmt.Sprintf("%s %q: %v", gvk.Kind, o.GetName(), err)
			}
			var ri dynamic.ResourceInterface = dc.Resource(m.Resource)
			if m.Scope.Name() == meta.RESTScopeNameNamespace {
				if o.GetNamespace() == "" {
					o.SetNamespace(t.GetName())
				}
				ri = dc.Resource(m.Resource).Namespace(o.GetNamespace())
			}
			if _, err := ri.Apply(r.Context(), o.GetName(), o, metav1.ApplyOptions{FieldManager: "ctrlplane-web", Force: true}); err != nil {
				return fmt.Sprintf("%s %q: %v", gvk.Kind, o.GetName(), err)
			}
		}
		return ""
	}()
	toast(rw, d.Error, "Applied "+plural(applied, "object"))
	w.loadResources(r.Context(), t, user, d)
	w.render(rw, "resources", d)
}

func (w *web) deleteResource(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := &tenantData{Name: t.GetName()}
	q := r.URL.Query()
	gvr := schema.GroupVersionResource{Group: q.Get("group"), Version: q.Get("version"), Resource: q.Get("resource")}
	if dc, err := w.tenantClient(r.Context(), t, user); err != nil {
		d.Error = err.Error()
	} else if err := dc.Resource(gvr).Namespace(q.Get("namespace")).Delete(r.Context(), q.Get("name"), metav1.DeleteOptions{}); client.IgnoreNotFound(err) != nil {
		d.Error = err.Error()
	}
	toast(rw, d.Error, "Deleted "+q.Get("name"))
	w.loadResources(r.Context(), t, user, d)
	w.render(rw, "resources", d)
}

// loadResources lists the objects of every established CRD (its storage version).
// ponytail: one List per CRD per render; fine for a handful of operators.
func (w *web) loadResources(ctx context.Context, t *platformv1alpha1.Tenant, user string, d *tenantData) {
	cfg, err := w.tenantConfig(ctx, t, user)
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	crds, err := dc.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	hc, err := rest.HTTPClientFor(cfg) // carries the impersonation: the tenant's RBAC applies
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	for _, c := range crds.Items {
		k := kindTable{}
		k.Kind, _, _ = unstructured.NestedString(c.Object, "spec", "names", "kind")
		k.Group, _, _ = unstructured.NestedString(c.Object, "spec", "group")
		k.Resource, _, _ = unstructured.NestedString(c.Object, "spec", "names", "plural")
		scope, _, _ := unstructured.NestedString(c.Object, "spec", "scope")
		k.Namespaced = scope == "Namespaced"
		versions, _, _ := unstructured.NestedSlice(c.Object, "spec", "versions")
		for _, v := range versions {
			if m, _ := v.(map[string]any); m["storage"] == true {
				k.Version, _ = m["name"].(string)
			}
		}
		if err := k.load(ctx, hc, cfg.Host); err != nil {
			k.Error = err.Error()
		}
		d.ResourceCount += len(k.Rows)
		d.Kinds = append(d.Kinds, k)
	}
	slices.SortFunc(d.Kinds, func(a, b kindTable) int { return cmp.Compare(a.Kind, b.Kind) })
}

// load fills k from the API server's Table for its type in all namespaces (as `kubectl get -A`):
// the columns kubectl shows by default (priority 0), the name kept apart to link it.
func (k *kindTable) load(ctx context.Context, hc *http.Client, host string) error {
	u := strings.TrimSuffix(host, "/") + "/apis/" + k.Group + "/" + k.Version + "/" + k.Resource + "?includeObject=Metadata"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		st := &metav1.Status{}
		if json.NewDecoder(resp.Body).Decode(st) == nil && st.Message != "" {
			return errors.New(st.Message)
		}
		return fmt.Errorf("listing %s: %s", k.Resource, resp.Status)
	}
	tbl := &metav1.Table{}
	if err := json.NewDecoder(resp.Body).Decode(tbl); err != nil {
		return err
	}
	var show []int
	for i, c := range tbl.ColumnDefinitions {
		if c.Priority == 0 && c.Name != "Name" {
			show = append(show, i)
			k.Columns = append(k.Columns, strings.ToUpper(c.Name))
		}
	}
	// The API server adds AGE only to types without printer columns of their own: add it to the rest.
	addAge := !slices.Contains(k.Columns, "AGE")
	if addAge {
		k.Columns = append(k.Columns, "AGE")
	}
	for _, row := range tbl.Rows {
		m := metav1.PartialObjectMetadata{}
		_ = json.Unmarshal(row.Object.Raw, &m)
		r := kindRow{Name: m.Name, Namespace: m.Namespace}
		for _, i := range show {
			if i < len(row.Cells) {
				r.Cells = append(r.Cells, cellText(row.Cells[i]))
			}
		}
		if addAge {
			r.Cells = append(r.Cells, duration.HumanDuration(time.Since(m.CreationTimestamp.Time)))
		}
		k.Rows = append(k.Rows, r)
	}
	return nil
}

// cellText prints a Table cell like kubectl does.
func cellText(v any) string {
	switch x := v.(type) {
	case nil:
		return "<none>"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

// objectTarget is the object a request names: ?crd=<name> for an API type, else
// group/version/resource/namespace/name (form values for a save).
func objectTarget(get func(string) string) (gvr schema.GroupVersionResource, ns, name string, crd bool) {
	if c := get("crd"); c != "" {
		return crdGVR, "", c, true
	}
	return schema.GroupVersionResource{Group: get("group"), Version: get("version"), Resource: get("resource")}, get("namespace"), get("name"), false
}

// objectYAML is o as YAML, without managedFields (bookkeeping nobody edits).
func objectYAML(o *unstructured.Unstructured) string {
	unstructured.RemoveNestedField(o.Object, "metadata", "managedFields")
	b, _ := yaml.Marshal(o.Object)
	return string(b)
}

func (v *objectView) fill(o *unstructured.Unstructured) {
	v.Kind, v.Name, v.Namespace, v.APIVersion = o.GetKind(), o.GetName(), o.GetNamespace(), o.GetAPIVersion()
	v.TypeKind, _, _ = unstructured.NestedString(o.Object, "spec", "names", "kind")
	v.YAML = objectYAML(o)
}

// object shows one CRD or custom resource as YAML, read as the user (their RBAC applies).
func (w *web) object(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	gvr, ns, name, crd := objectTarget(r.URL.Query().Get)
	v := objectView{Tenant: t.GetName(), Name: name, Namespace: ns, Group: gvr.Group, Version: gvr.Version, Resource: gvr.Resource, CRD: crd}
	dc, err := w.tenantClient(r.Context(), t, user)
	if err == nil {
		var o *unstructured.Unstructured
		if o, err = dc.Resource(gvr).Namespace(ns).Get(r.Context(), name, metav1.GetOptions{}); err == nil {
			v.fill(o)
		}
	}
	v.Error = errText(err)
	w.render(rw, "object", v)
}

// saveObject replaces one object with the edited YAML (an update as the user, so RBAC, schemas
// and admission apply). It must stay the same object: no renames, moves or other types.
func (w *web) saveObject(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, maxManifest)
	gvr, ns, name, crd := objectTarget(r.FormValue)
	v := objectView{Tenant: t.GetName(), Name: name, Namespace: ns, Group: gvr.Group, Version: gvr.Version, Resource: gvr.Resource, CRD: crd,
		YAML: r.FormValue("yaml"), Editing: true}
	o := &unstructured.Unstructured{}
	err := yaml.Unmarshal([]byte(v.YAML), &o.Object)
	switch wantAPI := gvr.GroupVersion().String(); {
	case err != nil:
		err = fmt.Errorf("invalid YAML: %w", err)
	case o.Object == nil:
		err = errString("nothing to save")
	case o.GetAPIVersion() != wantAPI:
		err = fmt.Errorf("apiVersion must stay %s", wantAPI)
	case o.GetName() != name || o.GetNamespace() != ns:
		err = errString("the name and namespace can't change here; apply a new object instead")
	default:
		var dc dynamic.Interface
		if dc, err = w.tenantClient(r.Context(), t, user); err == nil {
			var saved *unstructured.Unstructured
			if saved, err = dc.Resource(gvr).Namespace(ns).Update(r.Context(), o, metav1.UpdateOptions{FieldManager: "ctrlplane-web"}); err == nil {
				v.fill(saved)
				v.Editing = false
			} else if apierrors.IsConflict(err) {
				err = errString("it changed since you opened it: close it and open it again to edit the latest")
			}
		}
	}
	if v.Kind == "" {
		v.Kind = o.GetKind()
	}
	v.Error = errText(err)
	toast(rw, v.Error, "Saved "+name, "objects-changed")
	w.render(rw, "object", v)
}

// metrics answers the page's charts: Prometheus query / query_range, asked of the tenant API
// server as the user, whose /platform/metrics only ever returns this tenant's series.
func (w *web) metrics(rw http.ResponseWriter, r *http.Request, user string) {
	if api := r.PathValue("api"); api == "query" || api == "query_range" {
		w.tenantQuery(rw, r, user, "/platform/metrics/api/v1", api)
	} else {
		http.NotFound(rw, r)
	}
}

// logs answers the page's log search: LogsQL query (matching lines) and hits (counts over
// time), asked as the user of /platform/logs, which only ever returns this tenant's streams.
func (w *web) logs(rw http.ResponseWriter, r *http.Request, user string) {
	if api := r.PathValue("api"); api == "query" || api == "hits" {
		w.tenantQuery(rw, r, user, "/platform/logs/select/logsql", api)
	} else {
		http.NotFound(rw, r)
	}
}

// tenantQuery forwards r's query parameters to <path>/<api> on the tenant API server as user.
func (w *web) tenantQuery(rw http.ResponseWriter, r *http.Request, user, path, api string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	cfg, err := w.tenantConfig(r.Context(), t, user)
	var cs *kubernetes.Clientset
	if err == nil {
		cs, err = kubernetes.NewForConfig(cfg)
	}
	if err == nil {
		req := cs.CoreV1().RESTClient().Get().AbsPath(path, api)
		for k, vs := range r.URL.Query() {
			for _, v := range vs {
				req.Param(k, v)
			}
		}
		var b []byte
		if b, err = req.Do(r.Context()).Raw(); err == nil {
			_, _ = rw.Write(b)
			return
		}
	}
	rw.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(rw).Encode(map[string]string{"status": "error", "error": err.Error()})
}

// events lists the control plane's recent events: its namespace, plus "default", where events
// about cluster-scoped objects go. Read as the user, so tenant RBAC decides.
func (w *web) events(rw http.ResponseWriter, r *http.Request, user string) {
	if t, ok := w.ownedTenant(rw, r, user); ok {
		d := &tenantData{Name: t.GetName(), WarningsOnly: r.URL.Query().Get("type") == "Warning"}
		w.loadEvents(r.Context(), t, user, d)
		w.render(rw, "events", d)
	}
}

func (w *web) loadEvents(ctx context.Context, t *platformv1alpha1.Tenant, user string, d *tenantData) {
	cfg, err := w.tenantConfig(ctx, t, user)
	var cs *kubernetes.Clientset
	if err == nil {
		cs, err = kubernetes.NewForConfig(cfg)
	}
	if err != nil {
		d.Error = cmp.Or(d.Error, err.Error())
		return
	}
	opts := metav1.ListOptions{}
	if d.WarningsOnly {
		opts.FieldSelector = "type=Warning"
	}
	var all []eventsv1.Event
	for _, ns := range []string{t.GetName(), metav1.NamespaceDefault} {
		list, err := cs.EventsV1().Events(ns).List(ctx, opts)
		if err != nil {
			d.Error = cmp.Or(d.Error, err.Error())
			continue
		}
		all = append(all, list.Items...)
	}
	slices.SortFunc(all, func(a, b eventsv1.Event) int { return lastSeen(&b).Compare(lastSeen(&a)) })
	for _, e := range all[:min(len(all), 50)] {
		obj := strings.ToLower(e.Regarding.Kind) + "/" + e.Regarding.Name
		if e.Regarding.Namespace != "" && e.Regarding.Namespace != t.GetName() {
			obj = e.Regarding.Namespace + "/" + obj
		}
		v := eventView{Age: duration.HumanDuration(time.Since(lastSeen(&e))), Type: e.Type, Object: obj,
			Reason: e.Reason, Note: e.Note, By: cmp.Or(e.ReportingController, e.DeprecatedSource.Component), Count: eventCount(&e)}
		d.Events = append(d.Events, v)
		if v.Type != "Warning" {
			continue
		}
		// The overview shows each distinct warning once (newest), with how often it happened.
		if i := slices.IndexFunc(d.Warnings, func(o eventView) bool { return o.Reason == v.Reason && o.Object == v.Object }); i >= 0 {
			d.Warnings[i].Count += v.Count
		} else if len(d.Warnings) < 5 {
			d.Warnings = append(d.Warnings, v)
		}
	}
}

type logsData struct {
	Tenant, Controller, Logs, Error string
	Previous                        bool
}

// controllerLogs shows the last lines of a controller's newest pod (or its previous run,
// for crash loops) via the tenant API server's /platform/controllers/<name>/logs.
func (w *web) controllerLogs(rw http.ResponseWriter, r *http.Request, user string) {
	t, ok := w.ownedTenant(rw, r, user)
	if !ok {
		return
	}
	d := logsData{Tenant: t.GetName(), Controller: r.PathValue("controller"), Previous: r.URL.Query().Get("previous") == "true"}
	cfg, err := w.tenantConfig(r.Context(), t, user)
	if err == nil {
		var cs *kubernetes.Clientset
		if cs, err = kubernetes.NewForConfig(cfg); err == nil {
			var b []byte
			b, err = cs.CoreV1().RESTClient().Get().AbsPath("/platform/controllers", d.Controller, "logs").
				Param("tailLines", "300").Param("timestamps", "true").Param("previous", strconv.FormatBool(d.Previous)).
				Do(r.Context()).Raw()
			d.Logs = string(b)
		}
	}
	if err != nil {
		d.Logs, d.Error = "", err.Error()
	}
	w.render(rw, "logs", d)
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

const maxManifest = 8 << 20

const maxManifestURLs = 10

// manifestClient fetches user-supplied manifest URLs. It runs inside the platform, so it
// only connects to public IPs (checked per connection: covers redirects and DNS rebinding),
// never the host cluster, tenant API servers, metadata endpoints or the LAN.
var manifestClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if !publicIP(net.ParseIP(host)) {
			return fmt.Errorf("refusing to connect to non-public address %s", host)
		}
		return nil
	}}).DialContext
	return &http.Client{Transport: t, Timeout: 30 * time.Second}
}()

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func publicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

func fetchManifest(ctx context.Context, rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return "", errors.New("only https:// URLs")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := manifestClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxManifest {
		return "", fmt.Errorf("larger than %d MiB", maxManifest>>20)
	}
	return string(b), nil
}
