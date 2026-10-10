#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Renews the listener certificate from pki-listener/ once it has RENEW_DAYS left, then reloads
# bao with SIGHUP so the new certificate serves without a restart or a seal.
#   renew-listener.sh once | loop
set -euo pipefail
TLS_DIR=${TLS_DIR:-/bao/data/tls}
RENEW_DIR=${RENEW_DIR:-$TLS_DIR/renewed}
RENEW_DAYS=${RENEW_DAYS:-30}
RENEW_EVERY=${RENEW_EVERY:-43200}
LISTENER_ADDR=${LISTENER_ADDR:-127.0.0.1:8200}
SERVER_NAME=weftspun-bao.internal
ALT_NAMES=${LISTENER_ALT_NAMES:-weftspun-bao.fly.dev,localhost,weftspun-bao.stonecat-ratio.ts.net,weftspun-bao-1.stonecat-ratio.ts.net}

log() { echo "renew-listener: $*"; }

serving_serial() {
	openssl s_client -connect "$LISTENER_ADDR" -servername "$SERVER_NAME" \
		-cert "$TLS_DIR/listener-cert.pem" -key "$TLS_DIR/listener-key.pem" </dev/null 2>/dev/null \
		| openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

renew_once() {
	local cert=$TLS_DIR/listener-cert.pem key=$TLS_DIR/listener-key.pem
	log "serving until $(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
	if openssl x509 -in "$cert" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null; then
		return 0
	fi
	mkdir -p "$RENEW_DIR"
	local w
	w=$(mktemp -d "$RENEW_DIR/.new.XXXX")
	trap 'rm -rf "$w"' EXIT
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$SERVER_NAME" \
		-keyout "$w/key.pem" -out "$w/req.csr" 2>/dev/null
	export BAO_ADDR=https://$LISTENER_ADDR BAO_TLS_SERVER_NAME=$SERVER_NAME BAO_CACERT=$TLS_DIR/ca-chain.pem \
		BAO_CLIENT_CERT=$cert BAO_CLIENT_KEY=$key
	BAO_TOKEN=$(bao login -method=cert -no-store -token-only name=bao-listener)
	export BAO_TOKEN
	local leaf ca
	leaf=$(bao write -field=certificate pki-listener/sign/listener csr=@"$w/req.csr" \
		common_name=$SERVER_NAME alt_names="$ALT_NAMES")
	ca=$(bao read -field=certificate pki-listener/cert/ca)
	# -field prints no trailing newline, and PEM blocks joined without one do not parse.
	printf '%s\n' "$leaf" >"$w/leaf.pem"
	printf '%s\n' "$ca" >"$w/ca.pem"
	unset BAO_TOKEN
	openssl verify -CAfile "$TLS_DIR/ca-chain.pem" -untrusted "$w/ca.pem" "$w/leaf.pem" >/dev/null
	[ "$(cat "$w/leaf.pem" "$w/ca.pem" | grep -c 'BEGIN CERTIFICATE')" = 2 ]
	[ "$(openssl x509 -in "$w/leaf.pem" -noout -pubkey)" = "$(openssl pkey -in "$w/key.pem" -pubout)" ]
	cat "$w/leaf.pem" "$w/ca.pem" >"$w/cert.pem"
	chmod 600 "$w/key.pem"
	cp "$w/cert.pem" "$w/key.pem" "$RENEW_DIR/"
	mv "$RENEW_DIR/cert.pem" "$RENEW_DIR/listener-cert.pem"
	mv "$RENEW_DIR/key.pem" "$RENEW_DIR/listener-key.pem"
	cp "$w/key.pem" "$key.new" && cp "$w/cert.pem" "$cert.new"
	mv "$key.new" "$key" && mv "$cert.new" "$cert"
	local want
	want=$(openssl x509 -in "$cert" -noout -serial | cut -d= -f2)
	pkill -HUP -f '^bao server' || pkill -HUP -x bao
	for _ in $(seq 1 20); do
		if [ "$(serving_serial)" = "$want" ]; then
			log "renewed: serial $want, until $(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
			return 0
		fi
		sleep 1
	done
	log "FAIL: wrote serial $want but the listener still serves $(serving_serial)"
	return 1
}

case "${1:-loop}" in
once) renew_once ;;
loop)
	# Each pass runs as its own process: errexit is off inside a function called from `if`.
	while true; do
		if "$0" once; then
			sleep "$RENEW_EVERY"
		else
			log "WARN: renewal failed; next try in ${RETRY_EVERY:-600}s"
			sleep "${RETRY_EVERY:-600}"
		fi
	done
	;;
*) echo "usage: renew-listener.sh once|loop" >&2; exit 2 ;;
esac
