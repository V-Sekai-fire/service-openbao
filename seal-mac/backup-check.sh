#!/bin/bash
# Compares the live transit key's fingerprint with the one recorded when it was saved to 1Password (RFD 2147).
set -uo pipefail
P="$HOME/Library/Application Support/bao-seal/pki"
export BAO_ADDR="https://$(tailscale ip -4):8210" BAO_TLS_SERVER_NAME=bao-seal.internal BAO_CACERT="$P/root.pem" \
  BAO_CLIENT_CERT="$P/client-prod.pem" BAO_CLIENT_KEY="$P/client-prod.key"
BAO_TOKEN=$(security find-generic-password -s bao-seal-root-token -w) || { echo "FAIL: no root token in Keychain"; exit 2; }
export BAO_TOKEN
rec=$(security find-generic-password -s bao-seal-backup-fingerprint -w) || { echo "FAIL: no backup record in Keychain"; exit 2; }
live=$(bao read -format=json transit/export/encryption-key/fly-bao-prod 2>/dev/null | python3 -c \
  'import json,sys,hashlib;k=json.load(sys.stdin)["data"]["keys"];print(hashlib.sha256(json.dumps(k,sort_keys=True).encode()).hexdigest()[:16])') \
  || { echo "FAIL: seal Bao unreachable or sealed"; exit 2; }
if [ "$live" = "${rec#*:}" ]; then echo "OK: fly-bao-prod $live matches 1Password item ${rec%%:*}"; exit 0; fi
echo "DRIFT: live fly-bao-prod $live, 1Password item ${rec%%:*} has ${rec#*:}; save a new backup"; exit 1
