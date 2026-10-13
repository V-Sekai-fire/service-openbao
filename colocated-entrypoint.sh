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
  while :; do
    /usr/local/bin/bao-entrypoint.sh || true
    echo "bao exited; restarting in 10s (it comes back sealed)"
    sleep 10
  done
}

if [ "${WEFT_BAO:-1}" = 1 ]; then
  ( bao_beside 2>&1 | sed -u 's/^/[bao] /' ) &
fi
exec /usr/local/bin/fdb-entrypoint.sh
