# The build runs natively and cross-compiles for each --platform (no emulation).
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
# Cache mounts keep the module and build caches (GBs, with the Kubernetes deps) out of the layers.
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# -s drops symbols + DWARF (implies -w); -trimpath drops local paths.
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags=-s -o /out/tenant-apiserver ./cmd/tenant-apiserver && \
    go build -trimpath -ldflags=-s -o /out/platform ./cmd/platform

# One image per binary: `docker build --target tenant-apiserver|platform`.
FROM gcr.io/distroless/static:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087 AS tenant-apiserver
COPY --from=build /out/tenant-apiserver /
ENTRYPOINT ["/tenant-apiserver"]

FROM gcr.io/distroless/static:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087 AS platform
COPY --from=build /out/platform /
ENTRYPOINT ["/platform"]
