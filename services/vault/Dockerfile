# Images are pinned by digest. Update tag AND digest together.

FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go vet ./... \
 && go test ./... \
 && go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/vault . \
 && mkdir -p /out/data /out/snapshots

# Distroless: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/vault /vault
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
COPY --from=build --chown=65532:65532 --chmod=0700 /out/snapshots /snapshots
USER 65532:65532
ENV VAULT_ADDR=0.0.0.0:8080 \
    VAULT_DATA_DIR=/data \
    VAULT_SNAPSHOT_DIR=/snapshots \
    VAULT_TRUST_PROXY=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/vault", "healthcheck"]
ENTRYPOINT ["/vault"]
