#!/bin/bash
# The Mac mini's transit Bao (RFD 2147): seal key and listener key come from the login Keychain.
set -euo pipefail
DIR="$HOME/Library/Application Support/bao-seal"
RUN=$(mktemp -d "${TMPDIR:-/tmp}/bao-seal.XXXX")
trap 'rm -rf "$RUN"' EXIT
ADDR=$(tailscale ip -4)
security find-generic-password -s bao-seal-listener-key -w | base64 -d > "$RUN/listener.key"
chmod 600 "$RUN/listener.key"
sed -e "s|@DIR@|$DIR|g" -e "s|@RUN@|$RUN|g" -e "s|@ADDR@|$ADDR|g" "$(dirname "$0")/config.hcl.tmpl" > "$RUN/config.hcl"
BAO_SEAL_KEY=$(security find-generic-password -s bao-seal-static-key -w)
export BAO_SEAL_KEY
( sleep 15; rm -f "$RUN/listener.key" ) &
bao server -config="$RUN/config.hcl"
