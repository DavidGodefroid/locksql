# locksql in Docker: the separated setup of `locksql install`, baked into an
# image. The console runs as "locksql" in one container; the agent's MCP
# server runs as "agent" in another; they share the socket directory through
# a named volume, and the kernel checks every peer as it does on a host.
# See docs/docker.md.
#
#   docker build -t locksql .
#   docker build --target vault -t locksql .   # with the vault CLI, for credentials = "vault"

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/locksql ./cmd/locksql

# The HashiCorp Vault CLI, checked against the sums pinned here (update them
# with VAULT_VERSION from releases.hashicorp.com/vault/<version>/).
FROM alpine:3.22 AS vault-cli
ARG TARGETARCH
ARG VAULT_VERSION=2.2.0
ARG VAULT_SHA256_amd64=05d78b0ac842ca7c522fc297df91527cd43c15420c4c5c0a969d48a7b0ff7b6d
ARG VAULT_SHA256_arm64=9d9ae0ce520744fb095bdf150a6924f5583528fd385a2e92782f7a6d00cad53c
RUN set -eu; arch=${TARGETARCH:-amd64}; \
    case $arch in amd64) sum=$VAULT_SHA256_amd64 ;; arm64) sum=$VAULT_SHA256_arm64 ;; *) echo "no vault CLI for $arch" >&2; exit 1 ;; esac; \
    wget -qO /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${arch}.zip"; \
    echo "$sum  /tmp/vault.zip" | sha256sum -c -; \
    unzip -q /tmp/vault.zip vault -d /out

FROM alpine:3.22 AS console
# ALLOWED_UIDS: comma-separated uids that may reach the console besides the
# members of locksql-clients, for an agent in a container of its own whose
# uid has no account here (docs/docker.md#agent-in-its-own-container).
ARG ALLOWED_UIDS=""
# ca-certificates: tls = "verify-full" checks remote servers against them.
RUN case "$ALLOWED_UIDS" in *[!0-9,]*|,*|*,|*,,*) echo "ALLOWED_UIDS: comma-separated uids, got '$ALLOWED_UIDS'" >&2; exit 1;; esac \
 && apk add --no-cache ca-certificates \
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
 && if [ -n "$ALLOWED_UIDS" ]; then printf 'allowed_uids = [%s]\n' "$ALLOWED_UIDS" >> /etc/locksql/system.toml; fi \
 && chmod 0644 /etc/locksql/system.toml \
 && install -d -m 2710 -o locksql -g locksql-clients /run/locksql
COPY --from=build --chown=root:root --chmod=0755 /out/locksql /usr/local/bin/locksql

# Named volumes take these directories' owner and mode on first use.
VOLUME ["/run/locksql", "/home/locksql"]
WORKDIR /
USER agent
ENTRYPOINT ["locksql"]
CMD ["help"]

# The console with the vault CLI (docs/docker.md, Credentials from Vault).
# Not the default: the CLI adds some 550 MB.
FROM console AS vault
COPY --from=vault-cli --chown=root:root --chmod=0755 /out/vault /usr/local/bin/vault

# The default image.
FROM console
