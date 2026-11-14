# Caddy without uid 0 and without any capabilities.
#
# Caddy is built from source (src/: stock v2.11.9 with standard modules) instead of
# copied from the official image, so that vulnerable transitive dependencies can be
# bumped without waiting for an upstream release. The official binary also carries the file capability
# cap_net_bind_service=+ep, which `cap_drop: ALL` would refuse to exec; a binary
# built with `go build` has no xattrs at all.
#   - runs on distroless (no shell, no package manager) as uid 65532;
#   - binds :80/:443 thanks to net.ipv4.ip_unprivileged_port_start=0 inside the
#     container's network namespace (docker-compose.yml sets it explicitly).
# CI runs the image with --cap-drop ALL as uid 65532: if a capability ever sneaks
# back onto the binary, exec fails and the build fails.
#
# Images are pinned by digest. Update tag AND digest together.
# Module versions are pinned in src/go.mod and verified against src/go.sum and GOSUMDB.

FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local
COPY src/go.mod src/go.sum ./
RUN go mod download && go mod verify
COPY src/main.go ./
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/caddy . \
 && mkdir -p /out/data /out/config

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/caddy /usr/bin/caddy
# New named volumes inherit the owner of these directories.
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/config /config
ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config
USER 65532:65532
EXPOSE 80 443 443/udp
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
