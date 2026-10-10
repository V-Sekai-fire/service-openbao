#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# One-time setup of pki-listener/, the issuer bao renews its own listener certificate from.
# Runs with a root token. The intermediate's key is generated inside bao and never leaves it.
#   listener-pki-setup.sh csr <out.csr>                    mount and request
#   listener-pki-setup.sh finish <intermediate.pem> <root.pem>   install, role, policy, login
set -euo pipefail
NAMES=weftspun-bao.internal,weftspun-bao.fly.dev,localhost,weftspun-bao.stonecat-ratio.ts.net,weftspun-bao-1.stonecat-ratio.ts.net

case "${1:-}" in
csr)
	bao secrets list -format=json | grep -q '"pki-listener/"' ||
		bao secrets enable -path=pki-listener -max-lease-ttl=87600h pki
	bao write -field=csr pki-listener/intermediate/generate/internal \
		common_name="chibifire.com bao listener CA" key_type=ec key_bits=256 >"$2"
	;;
finish)
	cat "$2" "$3" >"$2.chain"
	bao write pki-listener/intermediate/set-signed certificate=@"$2.chain" >/dev/null
	rm -f "$2.chain"
	bao write pki-listener/roles/listener allowed_domains="$NAMES" allow_bare_domains=true \
		allow_subdomains=false allow_localhost=true allow_ip_sans=false enforce_hostnames=true \
		use_csr_common_name=false use_csr_sans=false server_flag=true client_flag=true \
		key_type=ec key_bits=256 ttl=2160h max_ttl=2160h no_store=true >/dev/null
	printf 'path "pki-listener/sign/listener" {\n  capabilities = ["update"]\n}\n' |
		bao policy write bao-listener-renew - >/dev/null
	bao write auth/cert/certs/bao-listener display_name=bao-listener certificate=@"$2" \
		allowed_dns_sans=weftspun-bao.internal token_policies=bao-listener-renew \
		token_no_default_policy=true token_ttl=300 token_max_ttl=300 >/dev/null
	echo "pki-listener ready: $(bao read -field=certificate pki-listener/cert/ca | openssl x509 -noout -subject -enddate | tr '\n' ' ')"
	;;
*) echo "usage: listener-pki-setup.sh csr <out.csr> | finish <intermediate.pem> <root.pem>" >&2; exit 2 ;;
esac
