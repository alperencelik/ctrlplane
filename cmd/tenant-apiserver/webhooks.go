package main

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	apiextensionsapiserver "k8s.io/apiextensions-apiserver/pkg/apiserver"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/admission"
	webhookinit "k8s.io/apiserver/pkg/admission/plugin/webhook/initializer"
	"k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/client-go/rest"
	aggregatorscheme "k8s.io/kube-aggregator/pkg/apiserver/scheme"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/controlplane"
	controlplaneapiserver "k8s.io/kubernetes/pkg/controlplane/apiserver"
	"k8s.io/kubernetes/pkg/controlplane/apiserver/options"
	"k8s.io/kubernetes/pkg/controlplane/apiserver/samples/generic/server"
	generatedopenapi "k8s.io/kubernetes/pkg/generated/openapi"
)

// newConfig is samples/generic/server.NewConfig with this tenant's webhook wiring: service
// references resolve to the platform's Services in the host namespace (tenantServices), and
// their certs are checked against the tenant CA too (withCA), so a webhook configuration or CRD
// pointing at ctrl-<controller>-webhook needs no caBundle. Without hostNS (standalone), upstream's.
func newConfig(opts options.CompletedOptions, tenantNS, hostNS string, ca []byte) (*server.Config, error) {
	if hostNS == "" {
		return server.NewConfig(opts)
	}
	c := &server.Config{Options: opts}
	genericConfig, versionedInformers, storageFactory, err := controlplaneapiserver.BuildGenericConfig(
		opts,
		[]*runtime.Scheme{legacyscheme.Scheme, apiextensionsapiserver.Scheme, aggregatorscheme.Scheme},
		controlplane.DefaultGenericAPIResourceConfigSource(),
		generatedopenapi.GetOpenAPIDefinitions,
		nil,
	)
	if err != nil {
		return nil, err
	}
	services := tenantServices{tenantNS: tenantNS, hostNS: hostNS}
	trustCA := func(r webhook.AuthenticationInfoResolver) webhook.AuthenticationInfoResolver {
		return tenantWebhooks{r, ca}
	}
	// Wraps the admission webhooks' default resolver (initializers run in order, each wrapper on the last).
	kubeAPIs, pluginInitializer, err := controlplaneapiserver.CreateConfig(opts, genericConfig, versionedInformers, nil, storageFactory, services,
		[]admission.PluginInitializer{webhookinit.NewPluginInitializer(trustCA, services)})
	if err != nil {
		return nil, err
	}
	c.ControlPlane = kubeAPIs

	authInfoResolver := webhook.NewDefaultAuthenticationInfoResolverWrapper(kubeAPIs.ProxyTransport, kubeAPIs.Generic.EgressSelector, kubeAPIs.Generic.LoopbackClientConfig, kubeAPIs.Generic.TracerProvider)
	conversionResolver := func(r webhook.AuthenticationInfoResolver) webhook.AuthenticationInfoResolver {
		return trustCA(authInfoResolver(r))
	}
	if c.APIExtensions, err = controlplaneapiserver.CreateAPIExtensionsConfig(*kubeAPIs.Generic, kubeAPIs.VersionedInformers, pluginInitializer, opts, 3, services, conversionResolver); err != nil {
		return nil, err
	}
	if c.Aggregator, err = controlplaneapiserver.CreateAggregatorConfig(*kubeAPIs.Generic, opts, kubeAPIs.VersionedInformers, services, kubeAPIs.ProxyTransport, kubeAPIs.Extra.PeerProxy, pluginInitializer); err != nil {
		return nil, err
	}
	c.Aggregator.ExtraConfig.DisableRemoteAvailableConditionController = true
	return c, nil
}

// tenantServices resolves service references (webhooks, conversion, APIServices): Service <name>
// in the tenant namespace is the platform's Service <name> in the host namespace, e.g. a
// controller's ctrl-<controller>-webhook. Other namespaces don't resolve, so a reference can't
// reach the host cluster's own Services.
type tenantServices struct{ tenantNS, hostNS string }

func (s tenantServices) ResolveEndpoint(namespace, name string, port int32) (*url.URL, error) {
	if namespace != s.tenantNS || len(validation.IsDNS1035Label(name)) > 0 {
		return nil, fmt.Errorf("service %s/%s: webhooks are Services in namespace %s, e.g. ctrl-<controller>-webhook", namespace, name, s.tenantNS)
	}
	return &url.URL{Scheme: "https", Host: net.JoinHostPort(name+"."+s.hostNS+".svc", strconv.Itoa(int(port)))}, nil
}

// tenantWebhooks gives service references no credentials (upstream's would send the API server's
// own to kubernetes.default) and trusts the tenant CA for them, besides any caBundle: it signs the
// controllers' webhook certs, and only certs the platform issues.
type tenantWebhooks struct {
	webhook.AuthenticationInfoResolver
	ca []byte
}

// ClientConfigFor (URLs, only the platform's: owners may not use them) never gets credentials
// either: upstream's gives the API server's loopback (system:masters) credentials to
// kubernetes.default.svc.
func (w tenantWebhooks) ClientConfigFor(string) (*rest.Config, error) {
	return &rest.Config{UserAgent: "kube-apiserver-admission", Timeout: 30 * time.Second}, nil
}

func (w tenantWebhooks) ClientConfigForService(string, string, int) (*rest.Config, error) {
	return &rest.Config{UserAgent: "kube-apiserver-admission", Timeout: 30 * time.Second,
		TLSClientConfig: rest.TLSClientConfig{CAData: bytes.Clone(w.ca)}}, nil // the caller appends the caBundle
}
