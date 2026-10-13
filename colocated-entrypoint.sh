#!/bin/bash
# FDB server in the foreground, Bao beside it as an FDB client of the same machine (RFD 2147).
set -euo pipefail

mkdir -p /data/bao
[ -L /bao/data ] || { rm -rf /bao/data; ln -s /data/bao /bao/data; }
if [ -n "${BAO_SSH_HOST_KEY_B64:-}" ]; then
  mkdir -p /data/bao/ssh
  printf '%s' "$BAO_SSH_HOST_KEY_B64" | base64 -d > /data/bao/ssh/ssh_host_ed25519_key
  chmod 600 /data/bao/ssh/ssh_host_ed25519_key
  ssh-keygen -y -f /data/bao/ssh/ssh_host_ed25519_key > /data/bao/ssh/ssh_host_ed25519_key.pub
fi

# Tailscale here rather than in the Bao entrypoint, so it is up before Bao asks the seal for its key.
tailnet() {
  [ -n "${TS_AUTHKEY:-}" ] || { echo "TS_AUTHKEY not set; no tailnet"; return 0; }
  mkdir -p /data/bao/tailscale /var/run/tailscale
  /usr/sbin/tailscaled --state="${WEFT_TS_STATE:-/data/bao/tailscale/tailscaled.state}" \
    --socket=/var/run/tailscale/tailscaled.sock --tun=userspace-networking &
  sleep 2
  timeout 30 tailscale up --authkey="$TS_AUTHKEY" --hostname="${WEFT_TS_HOSTNAME:-weftspun-bao}" \
    --advertise-tags=tag:fly-bao --accept-dns=false || echo "WARN: tailscale up failed"
}

# The transit seal is reached on loopback; socat carries it over the tailnet to the seal Bao.
seal_files() {
  [ -n "${WEFT_SEAL_TOKEN:-}" ] || return 0
  mkdir -p /run/bao-seal && chmod 700 /run/bao-seal
  printf '%s' "$WEFT_SEAL_CA_B64" | base64 -d > /run/bao-seal/ca.pem
  printf '%s' "$WEFT_SEAL_CERT_B64" | base64 -d > /run/bao-seal/cert.pem
  printf '%s' "$WEFT_SEAL_KEY_B64" | base64 -d > /run/bao-seal/key.pem
  chmod 600 /run/bao-seal/key.pem
  socat TCP-LISTEN:8210,bind=127.0.0.1,fork,reuseaddr \
    EXEC:"tailscale nc ${WEFT_SEAL_TS_ADDR:?} 8210" &
}

bao_config() {
  cp /bao/config/base.hcl /bao/config/config.hcl
  if [ -n "${WEFT_SEAL_TOKEN:-}" ] && [ -f /data/bao/seal-transit ]; then
    cat >> /bao/config/config.hcl <<HCL

seal "transit" {
  address         = "https://127.0.0.1:8210"
  token           = "$WEFT_SEAL_TOKEN"
  key_name        = "${WEFT_SEAL_KEY_NAME:?}"
  mount_path      = "transit/"
  tls_ca_cert     = "/run/bao-seal/ca.pem"
  tls_client_cert = "/run/bao-seal/cert.pem"
  tls_client_key  = "/run/bao-seal/key.pem"
  tls_server_name = "bao-seal.internal"
}
HCL
  fi
  chmod 600 /bao/config/config.hcl
}

bao_beside() {
  local t=/etc/foundationdb/tls
  until [ -s /etc/foundationdb/fdb.cluster ] && [ -s $t/cert.pem ] && [ -s $t/key.pem ]; do sleep 2; done
  # Bao reads the server's own cluster file and presents this machine's FDB leaf as its client cert.
  FDB_CLUSTER_CONTENT=$(cat /etc/foundationdb/fdb.cluster)
  FDB_TLS_CERT_B64=$(base64 -w0 $t/cert.pem)
  FDB_TLS_KEY_B64=$(base64 -w0 $t/key.pem)
  FDB_TLS_CA_B64=$(base64 -w0 $t/ca.pem)
  BAO_API_ADDR="https://${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:8200"
  BAO_CLUSTER_ADDR="https://${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:8201"
  export FDB_CLUSTER_CONTENT FDB_TLS_CERT_B64 FDB_TLS_KEY_B64 FDB_TLS_CA_B64 BAO_API_ADDR BAO_CLUSTER_ADDR
  tailnet
  seal_files
  while :; do
    while [ -f /data/bao/hold ]; do sleep 2; done
    bao_config
    TS_AUTHKEY= /usr/local/bin/bao-entrypoint.sh || true
    echo "bao exited; restarting in 10s"
    sleep 10
  done
}

if [ "${WEFT_BAO:-1}" = 1 ]; then
  ( bao_beside 2>&1 | sed -u 's/^/[bao] /' ) &
fi
exec /usr/local/bin/fdb-entrypoint.sh
