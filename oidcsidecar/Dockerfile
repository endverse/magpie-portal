# The OIDC sidecar beside magpie's own image: its own Go module, the same
# uid, and the same /config volume, so the keys it writes are the ones the
# gateway reads. Build from the repository root so the module's replace of
# github.com/yetone/magpie with ../ sees the gateway source:
#
#   docker build -f oidcsidecar/Dockerfile -t magpie-oidc .
#
# No file of magpie's own is changed. See oidcsidecar/docs/oidc-gateway.md.
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY oidcsidecar/go.mod oidcsidecar/go.sum ./oidcsidecar/

WORKDIR /src/oidcsidecar
RUN go mod download

WORKDIR /src
COPY . .

ARG VERSION=dev
WORKDIR /src/oidcsidecar
RUN CGO_ENABLED=0 go build -tags nogui -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/magpie-oidc ./cmd/magpie-oidc

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=build /out/magpie-oidc /magpie-oidc

# magpie's image runs as this uid and keeps everything under /config; the
# sidecar must match or the gateway cannot rewrite what it wrote.
ENV HOME=/config/home \
    XDG_CONFIG_HOME=/config \
    XDG_CACHE_HOME=/config/cache \
    XDG_DATA_HOME=/config/data \
    XDG_STATE_HOME=/config/state

USER 65532:65532

EXPOSE 3440

ENTRYPOINT ["/magpie-oidc"]
CMD ["-config", "/config/oidc.yaml"]
