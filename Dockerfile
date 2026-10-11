# locksql in Docker: the separated setup of `locksql install`, baked into an
# image. The console runs as "locksql" in one container; the agent's MCP
# server runs as "agent" in another; they share the socket directory through
# a named volume, and the kernel checks every peer as it does on a host.
# See docs/docker.md.
#
#   docker build -t locksql .

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/locksql ./cmd/locksql

FROM alpine:3.22
# ca-certificates: tls = "verify-full" checks remote servers against them.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10000 locksql-clients \
 && adduser -D -u 10001 -s /bin/sh -g "locksql console" locksql \
 && adduser -D -u 10002 -G locksql-clients -s /bin/sh -g "locksql agent" agent \
 && chmod 0700 /home/locksql \
 && install -d -m 0755 -o root -g root /etc/locksql \
 && printf '%s\n' \
      '# locksql: the console runs as service_user; members of client_group reach it.' \
      'service_user = "locksql"' \
      'client_group = "locksql-clients"' \
      'socket_dir   = "/run/locksql"' \
      'x11          = "refuse"' > /etc/locksql/system.toml \
 && chmod 0644 /etc/locksql/system.toml \
 && install -d -m 2710 -o locksql -g locksql-clients /run/locksql
COPY --from=build --chown=root:root --chmod=0755 /out/locksql /usr/local/bin/locksql

# Named volumes take these directories' owner and mode on first use.
VOLUME ["/run/locksql", "/home/locksql"]
WORKDIR /
USER agent
ENTRYPOINT ["locksql"]
CMD ["help"]
