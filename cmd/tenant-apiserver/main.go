// tenant-apiserver is one tenant's control plane: the upstream KEP-4080 generic
// control plane (no Pods/Nodes) with kine embedded as its etcd and the
// namespace, serviceaccount and garbage-collector controllers in-process.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/k3s-io/kine/pkg/endpoint"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/cli"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	_ "k8s.io/component-base/metrics/prometheus/clientgo"
	_ "k8s.io/component-base/metrics/prometheus/version"
	"k8s.io/kubernetes/pkg/controlplane/apiserver/options"
	"k8s.io/kubernetes/pkg/controlplane/apiserver/samples/generic/server"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "forward" {
		fmt.Fprintln(os.Stderr, forward("127.0.0.1:1080", os.Args[2:]))
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "restore" { // init container; see snapshot.go
		if err := restore(os.Getenv("RESTORE_URL"), os.Getenv("RESTORE_KEY"), "tenant.db"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) == 6 && os.Args[1] == "metrics-proxy" {
		fmt.Fprintln(os.Stderr, metricsProxy(os.Args[2], os.Args[3], os.Args[4], os.Args[5]))
		os.Exit(1)
	}
	opts := server.NewOptions()
	// ponytail: sqlite per tenant; pass postgres://… to share one DB server.
	datastore := "sqlite://./tenant.db?_journal=WAL&cache=shared&_busy_timeout=30000"
	hosts := []string{"localhost", "127.0.0.1"}
	var tenantNS, hostNS, metricsURL, logsURL string
	var owners []string

	// Secure defaults backed by ensurePKI; every one is still overridable by its flag.
	opts.SecureServing.ServerCert.CertKey.CertFile = pkiPath("apiserver.crt")
	opts.SecureServing.ServerCert.CertKey.KeyFile = pkiPath("apiserver.key")
	opts.Authentication.ClientCert.ClientCA = pkiPath("ca.crt")
	opts.Authentication.ServiceAccounts.KeyFiles = []string{pkiPath("sa.key")}
	opts.Authentication.ServiceAccounts.Issuers = []string{"https://kubernetes.default.svc"}
	opts.ServiceAccountSigningKeyFile = pkiPath("sa.key")
	opts.Authorization.Modes = []string{"RBAC"}
	// Tenants get only their own namespace plus kube-system, which the API server needs
	// (identity leases, bootstrap RBAC). No "default"; kube-public only held the node
	// bootstrap-signer role (no nodes here).
	opts.SystemNamespaces = []string{metav1.NamespaceSystem}
	delete(bootstrappolicy.NamespaceRoles(), metav1.NamespacePublic)
	delete(bootstrappolicy.NamespaceRoleBindings(), metav1.NamespacePublic)

	cmd := &cobra.Command{
		Use:          "tenant-apiserver",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := logsapi.ValidateAndApply(opts.Logs, utilfeature.DefaultFeatureGate); err != nil {
				return err
			}
			ctx := genericapiserver.SetupSignalContext()
			if err := ensurePKI(hosts, opts.SecureServing.BindPort, tenantNS); err != nil {
				return fmt.Errorf("pki: %w", err)
			}

			etcd, err := endpoint.Listen(ctx, endpoint.Config{
				Listener:            "unix://kine.sock",
				Endpoint:            datastore,
				NotifyInterval:      5 * time.Second,
				EmulatedETCDVersion: "3.6.11",
				CompactInterval:     5 * time.Minute,
				CompactTimeout:      5 * time.Second,
				CompactMinRetain:    1000,
				CompactBatchSize:    1000,
				PollBatchSize:       500,
			})
			if err != nil {
				return fmt.Errorf("kine: %w", err)
			}
			opts.Etcd.StorageConfig.Transport.ServerList = etcd.Endpoints

			completed, err := opts.Complete(ctx, nil, []net.IP{})
			if err != nil {
				return err
			}
			if errs := completed.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}
			dbPath := "" // the sqlite file, for /platform/snapshot
			if rest, ok := strings.CutPrefix(datastore, "sqlite://"); ok {
				dbPath, _, _ = strings.Cut(rest, "?")
			}
			return run(ctx, completed, tenantNS, hostNS, metricsURL, logsURL, dbPath, owners)
		},
	}

	var fss cliflag.NamedFlagSets
	opts.AddFlags(&fss)
	globalflag.AddGlobalFlags(fss.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	fss.FlagSet("tenant").StringVar(&datastore, "datastore", datastore, "kine datastore endpoint (sqlite://, postgres://, mysql://, nats://)")
	fss.FlagSet("tenant").StringSliceVar(&hosts, "tenant-hosts", hosts, "DNS names/IPs for the serving cert; the first one goes into pki/admin.kubeconfig")
	fss.FlagSet("tenant").StringVar(&tenantNS, "tenant-namespace", "", "namespace created at startup where platform-run controllers (group ctrlplane:controllers in their client certs) get full, namespace-scoped access")
	fss.FlagSet("tenant").StringSliceVar(&owners, "tenant-owners", nil, "usernames (as authenticated, e.g. github:alice) that manage CRDs and everything in --tenant-namespace")
	fss.FlagSet("tenant").StringVar(&hostNS, "host-namespace", "", "host-cluster namespace of this tenant; if set, serves /platform/controllers[/<name>/logs] using the in-cluster ServiceAccount")
	fss.FlagSet("tenant").StringVar(&metricsURL, "metrics-url", "", "VictoriaMetrics URL; with --host-namespace, serves /platform/metrics/api/v1/... restricted to that namespace's series")
	fss.FlagSet("tenant").StringVar(&logsURL, "logs-url", "", "VictoriaLogs URL; with --host-namespace, serves /platform/logs/select/logsql/... restricted to that namespace's streams")
	for _, fs := range fss.FlagSets {
		cmd.Flags().AddFlagSet(fs)
	}
	os.Exit(cli.Run(cmd))
}

// run mirrors samples/generic/server.Run, plus a post-start hook for controllers.
func run(ctx context.Context, opts options.CompletedOptions, tenantNS, hostNS, metricsURL, logsURL, dbPath string, owners []string) error {
	ca, err := os.ReadFile(pkiPath("ca.crt"))
	if err != nil {
		return err
	}
	config, err := newConfig(opts, tenantNS, hostNS, ca)
	if err != nil {
		return err
	}
	completed, err := config.Complete()
	if err != nil {
		return err
	}
	srv, err := server.CreateServerChain(completed)
	if err != nil {
		return err
	}
	if dbPath != "" {
		srv.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/platform/snapshot", snapshotHandler(dbPath))
	}
	if hostNS != "" {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("--host-namespace needs in-cluster credentials: %w", err)
		}
		host, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		h := controllersHandler(host, hostNS)
		srv.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/platform/controllers", h)
		srv.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/platform/controllers/", h)
		if metricsURL != "" {
			m, err := metricsHandler(metricsURL, hostNS)
			if err != nil {
				return err
			}
			srv.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/platform/metrics/", m)
		}
		if logsURL != "" {
			l, err := logsHandler(logsURL, hostNS)
			if err != nil {
				return err
			}
			srv.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/platform/logs/", l)
		}
	}
	if tenantNS != "" {
		// Synchronous: /readyz waits for every post-start hook, so the pod (and the site) only
		// report ready once the owners' and controllers' RBAC exists, not 15s of "forbidden" first.
		srv.GenericAPIServer.AddPostStartHookOrDie("tenant-bootstrap", func(hc genericapiserver.PostStartHookContext) error {
			bootstrapTenantNamespace(hc, hc.LoopbackClientConfig, tenantNS, owners)
			return nil
		})
	}
	srv.GenericAPIServer.AddPostStartHookOrDie("tenant-controllers", func(hc genericapiserver.PostStartHookContext) error {
		if tenantNS != "" {
			go syncCustomResourceRole(hc, hc.LoopbackClientConfig, tenantNS, owners)
		}
		return runControllers(hc, hc.LoopbackClientConfig)
	})
	prepared, err := srv.PrepareRun()
	if err != nil {
		return err
	}
	return prepared.Run(ctx)
}
