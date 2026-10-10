#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Local ladder for listener renewal: a throwaway root, an in-memory bao with the production
# listener settings, listener-pki-setup.sh, then renew-listener.sh. Each rung prints ok or FAIL.
#   checks/listener_renewal.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/listener-ladder.XXXX")
PORT=18200
FAILS=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
refused() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
cleanup() { [ -n "${BAO_PID:-}" ] && kill "$BAO_PID" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $T" || rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/tls"
cd "$T"

leaf() { # leaf <name> <cn> <eku> : signed by the throwaway root
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" \
		-keyout "$1.key" -out "$1.csr" 2>/dev/null
	printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' "$3" "$2" >"$1.ext"
	openssl x509 -req -in "$1.csr" -CA root.pem -CAkey root.key -set_serial "0x$(openssl rand -hex 16)" \
		-days "${4:-90}" -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=throwaway root" \
	-days 400 -keyout root.key -out root.pem 2>/dev/null
leaf listener weftspun-bao.internal serverAuth,clientAuth 20
leaf agent agent.test clientAuth
cp root.pem tls/ca-chain.pem
cp listener.pem tls/listener-cert.pem
cp listener.key tls/listener-key.pem
cat >bao.hcl <<EOF
storage "inmem" {}
disable_mlock = true
api_addr = "https://127.0.0.1:$PORT"
listener "tcp" {
  address = "127.0.0.1:$PORT"
  tls_cert_file = "$T/tls/listener-cert.pem"
  tls_key_file = "$T/tls/listener-key.pem"
  tls_client_ca_file = "$T/tls/ca-chain.pem"
  tls_require_and_verify_client_cert = true
  tls_min_version = "tls13"
}
EOF
bao server -config=bao.hcl >server.log 2>&1 &
BAO_PID=$!
export BAO_ADDR=https://127.0.0.1:$PORT BAO_TLS_SERVER_NAME=weftspun-bao.internal BAO_CACERT=$T/root.pem \
	BAO_CLIENT_CERT=$T/agent.pem BAO_CLIENT_KEY=$T/agent.key
for _ in $(seq 1 30); do bao status >/dev/null 2>&1; [ $? -ne 1 ] && break; sleep 0.5; done
bao operator init -key-shares=1 -key-threshold=1 -format=json >init.json
UNSEAL=$(python3 -c 'import json;print(json.load(open("init.json"))["unseal_keys_b64"][0])')
BAO_TOKEN=$(python3 -c 'import json;print(json.load(open("init.json"))["root_token"])')
export BAO_TOKEN
bao operator unseal "$UNSEAL" >/dev/null
bao auth enable cert >/dev/null

check "setup: pki-listener mounted and a CSR made inside bao" "$HERE/listener-pki-setup.sh" csr int.csr
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nnameConstraints=critical,permitted;DNS:weftspun-bao.internal,permitted;DNS:weftspun-bao.fly.dev,permitted;DNS:localhost,permitted;DNS:stonecat-ratio.ts.net\n' >int.ext
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -set_serial "0x$(openssl rand -hex 16)" \
	-days 399 -extfile int.ext -out int.pem 2>/dev/null
check "setup: intermediate installed, role, policy and login written" "$HERE/listener-pki-setup.sh" finish int.pem root.pem

run_renew() { env -u BAO_TOKEN -u BAO_CLIENT_CERT -u BAO_CLIENT_KEY TLS_DIR="$T/tls" LISTENER_ADDR=127.0.0.1:$PORT "$@"; }
serial() { openssl s_client -connect 127.0.0.1:$PORT -servername weftspun-bao.internal -cert agent.pem -key agent.key </dev/null 2>/dev/null | openssl x509 -noout -serial | cut -d= -f2; }

s0=$(serial)
check "the listener serves the bootstrap certificate (serial read)" test -n "$s0"
refused "control: the root-signed bootstrap certificate cannot log in to renew" run_renew RENEW_DAYS=100 "$HERE/renew-listener.sh" once
check "control: the listener still serves the old certificate after the refused renewal" test "$(serial)" = "$s0"

# Bootstrap, as production does: one certificate from the new issuer, installed by the operator.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=weftspun-bao.internal" \
	-keyout boot.key -out boot.csr 2>/dev/null
bao write -field=certificate pki-listener/sign/listener csr=@boot.csr common_name=weftspun-bao.internal \
	alt_names=localhost >boot.leaf
bao read -field=certificate pki-listener/cert/ca >boot.ca
{ cat boot.leaf; echo; cat boot.ca; echo; } >tls/listener-cert.pem
cp boot.key tls/listener-key.pem
kill -HUP "$BAO_PID"
sleep 2
s1=$(serial)
check "bootstrap: SIGHUP serves the certificate from pki-listener" test -n "$s1" -a "$s1" = "$(openssl x509 -in boot.leaf -noout -serial | cut -d= -f2)"
check "bootstrap: 90-day certificate" sh -c "openssl x509 -in boot.leaf -noout -checkend $((89 * 86400)) && ! openssl x509 -in boot.leaf -noout -checkend $((91 * 86400))"

check "a certificate with more than RENEW_DAYS left is kept" run_renew RENEW_DAYS=30 "$HERE/renew-listener.sh" once
check "  and the listener still serves it" test "$(serial)" = "$s1"
check "a certificate inside RENEW_DAYS is renewed and served after SIGHUP" run_renew RENEW_DAYS=100 "$HERE/renew-listener.sh" once
s2=$(serial)
check "  with a new serial" test -n "$s2" -a "$s2" != "$s1"
check "  by the same bao process, still unsealed" sh -c "kill -0 $BAO_PID && bao status -format=json | grep -q '\"sealed\": false'"
check "  and a copy kept in renewed/ for the next boot" cmp tls/renewed/listener-cert.pem tls/listener-cert.pem
check "the renewed certificate renews again" run_renew RENEW_DAYS=100 "$HERE/renew-listener.sh" once
test "$(serial)" != "$s2" && ok "  with another new serial" || bad "  with another new serial"

refused "control: the agent certificate (not from pki-listener) cannot log in to renew" \
	env -u BAO_TOKEN bao login -method=cert -no-store -token-only name=bao-listener
TOK=$(BAO_CLIENT_CERT=tls/listener-cert.pem BAO_CLIENT_KEY=tls/listener-key.pem bao login -method=cert -no-store -token-only name=bao-listener)
check "the renewed listener certificate logs in as bao-listener" test -n "$TOK"
refused "control: the renewal token cannot sign a name outside the listener's" \
	env BAO_TOKEN="$TOK" bao write -field=certificate pki-listener/sign/listener csr=@boot.csr common_name=evil.example
refused "control: the renewal token cannot read other secrets" env BAO_TOKEN="$TOK" bao secrets list
echo "RESULT: $([ $FAILS -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
exit $((FAILS > 0))
