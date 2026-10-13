storage "foundationdb" {
  api_version  = "730"
  cluster_file = "/etc/foundationdb/fdb.cluster"
  path         = "openbao"
  ha_enabled   = "true"
}

# Mutual TLS, enforced. tls_client_ca_file names the CA; the require flag is
# what makes a client cert mandatory — without it the listener accepts any
# TLS connection with no cert. Zero-trust: a 6PN neighbor is not trusted by
# position, it must present a cert this CA signed.
listener "tcp" {
  address                            = "[::]:8200"
  tls_cert_file                      = "/bao/data/tls/listener-cert.pem"
  tls_key_file                       = "/bao/data/tls/listener-key.pem"
  tls_client_ca_file                 = "/bao/data/tls/ca-chain.pem"
  tls_require_and_verify_client_cert = true
  tls_min_version                    = "tls13"
  # OpenBao gates the unauthenticated Shamir recovery endpoints behind these
  # toggles (Vault registers them by default). RFD 2144 defects #10 and #11:
  # sys/rekey/init returned 405 and sys/generate-root-token/attempt returned
  # 403 without these. The endpoints are still authenticated by holding one
  # unseal-key share -- the same trust boundary Vault always used.
  disable_unauthed_rekey_endpoints         = false
  disable_unauthed_generate_root_endpoints = false
}

ui            = false

# service-bao-sqlite-fdb is built into the image and lands here. It stays
# unregistered until an operator runs `bao plugin register` post-deploy.
plugin_directory = "/bao/plugins"
