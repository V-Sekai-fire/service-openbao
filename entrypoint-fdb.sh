#!/usr/bin/env bash
set -euo pipefail

# Tailscale sidecar (RFD 2195): private access from operator's tailnet peers.
# Fail-open: if TS_AUTHKEY is unset, Bao starts without Tailscale (internal
# Fly network still works). A future unset thus rolls back cleanly without
# breaking Bao.
if [ -n "${TS_AUTHKEY:-}" ]; then
  echo "Starting Tailscale sidecar..."
  # State on the volume, so a restart rejoins as the same node under the same name.
  mkdir -p /bao/data/tailscale /var/run/tailscale
  /usr/sbin/tailscaled \
      --state=/bao/data/tailscale/tailscaled.state \
      --socket=/var/run/tailscale/tailscaled.sock \
      --tun=userspace-networking &
  sleep 2
  # Timeout + background so a broken tag / bad key / control-plane hiccup
  # never blocks Bao startup. Fail-open per RFD 2195.
  (
    timeout 30 tailscale up \
        --authkey="${TS_AUTHKEY}" \
        --hostname=weftspun-bao \
        --advertise-tags=tag:fly-bao \
        --accept-dns=false \
      || echo "WARN: tailscale up failed or timed out; Bao continues without Tailscale"
  ) &
  disown %1 2>/dev/null || true
else
  echo "TS_AUTHKEY not set; Tailscale sidecar not started"
fi

TLS_DIR="/bao/data/tls"
mkdir -p "$TLS_DIR" /etc/foundationdb

if [ -z "${FDB_CLUSTER_CONTENT:-}" ]; then
  echo "FATAL: FDB_CLUSTER_CONTENT not set" >&2
  exit 1
fi
echo "$FDB_CLUSTER_CONTENT" > /etc/foundationdb/fdb.cluster
chmod 644 /etc/foundationdb/fdb.cluster

for var in FDB_TLS_CERT_B64 FDB_TLS_KEY_B64 FDB_TLS_CA_B64; do
  if [ -z "${!var:-}" ]; then
    echo "FATAL: $var not set" >&2
    exit 1
  fi
done

echo "$FDB_TLS_CERT_B64" | base64 -d > "$TLS_DIR/cert.pem"
echo "$FDB_TLS_KEY_B64"  | base64 -d > "$TLS_DIR/key.pem"
echo "$FDB_TLS_CA_B64"   | base64 -d > "$TLS_DIR/ca.pem"
chmod 600 "$TLS_DIR/key.pem"

CERT_CN=$(openssl x509 -in "$TLS_DIR/cert.pem" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
echo "FDB client cert CN=$CERT_CN"

export FDB_TLS_CERTIFICATE_FILE="$TLS_DIR/cert.pem"
export FDB_TLS_KEY_FILE="$TLS_DIR/key.pem"
export FDB_TLS_CA_FILE="$TLS_DIR/ca.pem"
export FDB_TLS_VERIFY_PEERS="Check.Valid=1,S.CN>=fdb-,S.CN<=.chibifire.com"

for var in BAO_TLS_CERT_B64 BAO_TLS_KEY_B64 BAO_TLS_CA_CHAIN_B64; do
  if [ -z "${!var:-}" ]; then
    echo "FATAL: $var not set" >&2
    exit 1
  fi
done

echo "$BAO_TLS_CERT_B64"      | base64 -d > "$TLS_DIR/listener-cert.pem"
echo "$BAO_TLS_KEY_B64"       | base64 -d > "$TLS_DIR/listener-key.pem"
echo "$BAO_TLS_CA_CHAIN_B64"  | base64 -d > "$TLS_DIR/ca-chain.pem"
chmod 600 "$TLS_DIR/listener-key.pem"

# A certificate renewed by renew-listener.sh outlives the one in the secret; serve whichever ends later.
RENEWED="$TLS_DIR/renewed"
enddate() { date -d "$(openssl x509 -in "$1" -noout -enddate | cut -d= -f2)" +%s; }
if [ -f "$RENEWED/listener-cert.pem" ] && [ -f "$RENEWED/listener-key.pem" ] &&
   [ "$(enddate "$RENEWED/listener-cert.pem")" -gt "$(enddate "$TLS_DIR/listener-cert.pem")" ]; then
  cp "$RENEWED/listener-cert.pem" "$TLS_DIR/listener-cert.pem"
  cp "$RENEWED/listener-key.pem" "$TLS_DIR/listener-key.pem"
  echo "Bao listener cert from renewed/"
fi

LISTENER_CN=$(openssl x509 -in "$TLS_DIR/listener-cert.pem" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
echo "Bao listener cert CN=$LISTENER_CN"

# Host key on the volume so the fingerprint survives a redeploy.
mkdir -p /bao/data/ssh /run/sshd
[ -f /bao/data/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /bao/data/ssh/ssh_host_ed25519_key
/usr/sbin/sshd || echo "WARN: sshd failed to start; Bao continues without the SSH tunnel"

echo "Waiting for FDB cluster..."
for i in $(seq 1 30); do
  if fdbcli --exec "status minimal" 2>/dev/null | grep -q "available"; then
    echo "FDB cluster available"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "FATAL: FDB cluster not available after 30s" >&2
    fdbcli --exec "status details" 2>&1 || true
    exit 1
  fi
  sleep 1
done

# BAO_RECOVERY=1 launches in recovery mode for orphan token cleanup / root
# regeneration. Recovery mode authenticates with the unseal key rather than a
# token, which is the intended path when the root token is lost. Set this as
# a fly secret when needed, redeploy, purge, unset, redeploy.
if [ "${BAO_RECOVERY:-0}" = 1 ]; then
  echo "STARTING IN RECOVERY MODE"
  exec dumb-init bao server -recovery -config=/bao/config/config.hcl
fi
/usr/local/bin/renew-listener.sh loop &
exec dumb-init bao server -config=/bao/config/config.hcl
