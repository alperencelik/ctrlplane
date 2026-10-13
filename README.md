# ctrlplane

A hosted Kubernetes control plane for the operators that manage your external resources
(hypervisor DNS, cloud resources etc.). Bring your CRDs and controller images; ctrlplane gives you your own API server and runs your controllers for you. No cluster, no nodes to look after.

It comes with what operators usually need, already wired up:

- **Observability:** your controllers' metrics, logs and events are collected and kept for you,
  searchable on the site or from your own Grafana.
- **Networking:** a tunnel you start from your own network lets your controllers reach the
  things they manage, with nothing exposed to the internet.
- **No hassle:** one command (`ctrlplane create dev`) gives you a control plane, and there's
  nothing to maintain after that: no upgrades, certificates or backups to look after. Sign in with
  kubectl and apply your CRDs and controllers, and the platform runs them for you.

Want to try it? [ctrlplane.run](https://ctrlplane.run) is the hosted platform: sign in with
GitHub and create a control plane without running anything yourself.

CLI: [ctrlplane-cli](https://github.com/alperencelik/ctrlplane-cli).

## Getting started

```sh
brew install alperencelik/tap/ctrlplane
ctrlplane login                    # sign in with GitHub
ctrlplane create dev --wait        # your own control plane
ctrlplane use dev                  # point kubectl at it
kubectl apply -f crds/             # your CRDs
ctrlplane deploy my-operator --image ghcr.io/you/my-operator:v1
```

## Building and testing

Needs Go (and Docker for the images).

```sh
make build              # bin/platform, bin/tenant-apiserver
make test               # go vet, unit tests, envtest (the reconciler against a real API server)
make lint               # gofmt, staticcheck, actionlint
make run-local          # one tenant API server on localhost:26443, no cluster needed
make image              # both container images
```

`make manifests generate` derives the CRDs (`config/crd`), the platform's ClusterRole
(`config/rbac`) and the deepcopy code from `api/` and the `+kubebuilder` markers.

## License

[Business Source License 1.1](LICENSE): free to use, modify and run, except to offer it
as a hosted service competing with ctrlplane.run. Each version becomes Apache 2.0 four years after
its release.
