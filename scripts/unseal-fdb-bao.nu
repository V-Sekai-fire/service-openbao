# Unseal each Bao beside the FDB server: one 1Password read, then sys/unseal per machine over flyctl ssh.
# Run from the desk console session (op needs the desktop app), e.g. a schtasks /IT task:
#   nu unseal-fdb-bao.nu weftspun-fdb <log> --item op://<vault>/<item> <machine-id>...
def main [app: string, log: string, --item: string, --dry-key: string = "", ...machines: string] {
  let fly = 'C:/Users/ernest.lee/scoop/apps/flyctl/current/flyctl.exe'
  let k = if ($dry_key | is-empty) {
    ^op read --no-newline $"($item)/unseal_key"
  } else { $dry_key }
  if ($k | str length) < 8 { "no key read\n" | save -a $log; exit 1 }
  let cmd = 'curl -s -m 20 --cert /bao/data/tls/listener-cert.pem --key /bao/data/tls/listener-key.pem --cacert /bao/data/tls/ca-chain.pem --resolve weftspun-bao.internal:8200:127.0.0.1 -X PUT --data-binary @- https://weftspun-bao.internal:8200/v1/sys/unseal'
  for m in $machines {
    let r = ({key: $k} | to json -r | ^$fly ssh console -a $app --machine $m -C $cmd | complete)
    let line = ($r.stdout | lines | where {|l| $l | str starts-with '{' } | get 0? | default '')
    let s = (try { $line | from json } catch { {} })
    $"($m) sealed=($s.sealed? | default 'unparsed') progress=($s.progress? | default '-') errors=($s.errors? | default [] | str join ';') exit=($r.exit_code)\n" | save -a $log
  }
  "done\n" | save -a $log
}
