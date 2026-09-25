#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Ladder for the Bao SSH tunnel: each rung must hold before the next is tried.

Run: tunnel_ladder.py [--remote HOST] [--control]
Local mode runs sshd_config itself under a throwaway CA; --remote attacks the deployed host.
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from hypothesis import HealthCheck, given, settings, strategies as st

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PORT = 12222
TARGET = ("127.0.0.1", 8200)
# A second listener the tunnel must never reach; a refused port would pass even with forwarding open.
DECOYS = [("127.0.0.1", 8199), ("127.0.0.1", 8201)]
EXAMPLES = settings(max_examples=12, deadline=None, derandomize=True,
                    suppress_health_check=list(HealthCheck))


def run(cmd, stdin=None, timeout=20):
    p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


class Desk:
    """Keys, CA and ssh options for one ladder run."""

    def __init__(self, work, host, port, known_hosts, ca_key=None):
        self.work, self.host, self.port, self.known_hosts, self.ca_key = work, host, port, known_hosts, ca_key
        self.key = os.path.join(work, "id")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key])

    def sign(self, principal="tunnel", validity="+1h", ca_key=None, name="cert"):
        src = os.path.join(self.work, name)
        shutil.copy(self.key + ".pub", src + ".pub")
        rc, _, err = run(["ssh-keygen", "-q", "-s", ca_key or self.ca_key, "-I", name, "-n", principal,
                          "-V", validity, "-O", "clear", "-O", "permit-port-forwarding", src + ".pub"])
        assert rc == 0, err
        return src + "-cert.pub"

    def ssh(self, *args, cert=None, user="tunnel", known_hosts=None, timeout=20, stdin=None):
        opts = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + (known_hosts or self.known_hosts),
                "-o", "HostKeyAlias=weftspun-bao", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                "-i", self.key, "-p", str(self.port)]
        if cert:
            opts += ["-o", "CertificateFile=" + cert]
        return run(["ssh"] + opts + list(args) + ["%s@%s" % (user, self.host)], stdin=stdin, timeout=timeout)

    def forward(self, cert, host, port, payload=b"ping\n"):
        return self.ssh("-W", "%s:%d" % (host, port), cert=cert, stdin=payload, timeout=8)


def echo_server():
    for addr in [TARGET] + DECOYS:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(addr)
        s.listen()

        def serve(s=s):
            while True:
                c, _ = s.accept()
                c.sendall(c.recv(64))
                c.close()
        threading.Thread(target=serve, daemon=True).start()


def local_sshd(work, weaken=None):
    ca = os.path.join(work, "ca")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ca])
    hostkey = os.path.join(work, "hostkey")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostkey])
    text = open(os.path.join(REPO, "sshd_config")).read()
    subs = {"Port ": "Port %d" % PORT, "HostKey ": "HostKey " + hostkey,
            "PidFile ": "PidFile " + os.path.join(work, "sshd.pid"),
            "TrustedUserCAKeys ": "TrustedUserCAKeys " + ca + ".pub"}
    lines = [next((v for k, v in subs.items() if ln.startswith(k)), ln) for ln in text.split("\n")]
    config = "\n".join(lines) + "\nPerSourcePenaltyExemptList 127.0.0.1,::1\n"
    if weaken:
        config = weaken(config)
    path = os.path.join(work, "sshd_config")
    open(path, "w").write(config)
    rc, _, err = run(["sudo", "/usr/sbin/sshd", "-t", "-f", path])
    if rc:
        raise SystemExit("rung 0 FAIL: sshd_config does not parse: " + err)
    run(["sudo", "/usr/sbin/sshd", "-f", path, "-E", os.path.join(work, "sshd.log")])
    time.sleep(0.5)
    known = os.path.join(work, "known_hosts")
    open(known, "w").write("weftspun-bao " + open(hostkey + ".pub").read())
    return ca, known


def ladder(desk, local):
    good = desk.sign() if local else os.environ["TUNNEL_CERT"]
    rungs = []

    # Refusal is judged by nothing getting through; auth-failure rungs run last so the
    # server's per-source penalties cannot mask the rungs that log in successfully.
    def rung(name):
        def wrap(fn):
            rungs.append((name, fn))
            return fn
        return wrap

    @rung("a pinned host key is required")
    def _():
        bogus = os.path.join(desk.work, "bogus_known_hosts")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", bogus + "_key"])
        open(bogus, "w").write("weftspun-bao " + open(bogus + "_key.pub").read())
        rc, _, err = desk.ssh("-N", "-o", "ExitOnForwardFailure=yes", cert=good, known_hosts=bogus, timeout=10)
        assert rc != 0 and "HOST IDENTIFICATION HAS CHANGED" in err, err

    @rung("the valid certificate reaches the listener")
    def _():
        rc, out, err = desk.forward(good, *TARGET, payload=b"" if not local else b"ping\n")
        assert rc == 0 and (not local or out == b"ping\n"), (rc, out, err)

    @rung("property: no other forward target opens")
    @EXAMPLES
    @given(st.sampled_from(DECOYS + [("localhost", 8199), ("::1", 8200), ("127.0.0.2", 8200)]))
    def _(target):
        rc, out, err = desk.forward(good, *target)
        assert rc != 0 and out == b"", (target, out, err)

    @rung("property: no command, shell or subsystem session opens")
    @EXAMPLES
    @given(st.sampled_from(["id", "sh -c id", "git-upload-pack x", "cat /etc/passwd", "true"]))
    def _(command):
        rc, out, err = desk.ssh(command, cert=good)
        assert rc != 0 and out == b"", (command, out, err)

    @rung("a pty, an sftp subsystem and a remote forward are all refused")
    def _():
        for args in (["-tt", "true"], ["-s", "sftp"], ["-N", "-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:1"]):
            rc, out, err = desk.ssh(*args, cert=good, timeout=10)
            assert rc != 0 and out == b"", (args, err)

    @rung("a key without a certificate is refused")
    def _():
        rc, out, err = desk.forward(None, *TARGET)
        assert rc != 0 and out == b"", (err or "dropped silently")

    if local:
        @rung("a certificate from another CA is refused")
        def _():
            other = os.path.join(desk.work, "otherca")
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other])
            rc, out, err = desk.forward(desk.sign(ca_key=other, name="other"), *TARGET)
            assert rc != 0 and out == b"", (err or "dropped silently")

        @rung("an expired certificate is refused")
        def _():
            rc, out, err = desk.forward(desk.sign(validity="-2h:-1h", name="expired"), *TARGET)
            assert rc != 0 and out == b"", (err or "dropped silently")

        @rung("property: no principal but tunnel logs in")
        @EXAMPLES
        @given(st.from_regex(r"[a-z][a-z0-9_-]{0,15}", fullmatch=True).filter(lambda p: p != "tunnel"))
        def _(principal):
            rc, out, err = desk.forward(desk.sign(principal=principal, name="p"), *TARGET)
            assert rc != 0 and out == b"", (principal, err)


    for i, (name, fn) in enumerate(rungs, 1):
        try:
            fn()
        except AssertionError as e:
            print("rung %d FAIL %s: %s" % (i, name, str(e)[:300]))
            return 1
        print("rung %d ok   %s" % (i, name))
    print("all %d rungs hold" % len(rungs))
    return 0


def local_run(weaken=None, quiet=False):
    work = tempfile.mkdtemp(prefix="tunnel-ladder-")
    os.chmod(work, 0o755)
    try:
        ca, known = local_sshd(work, weaken)
        desk = Desk(work, "127.0.0.1", PORT, known, ca)
        if quiet:
            with open(os.devnull, "w") as null:
                saved, sys.stdout = sys.stdout, null
                try:
                    return ladder(desk, True)
                finally:
                    sys.stdout = saved
        return ladder(desk, True)
    finally:
        pid = os.path.join(work, "sshd.pid")
        if not os.path.exists(pid):
            run(["sudo", "pkill", "-f", "sshd -f " + os.path.join(work, "sshd_config")])
        if os.path.exists(pid):
            run(["sudo", "kill", open(pid).read().strip()])
        shutil.rmtree(work, ignore_errors=True)


WEAKENED = {
    "PermitOpen any": lambda c: c.replace("PermitOpen 127.0.0.1:8200", "PermitOpen any"),
    "sessions allowed, no ForceCommand": lambda c: c.replace("MaxSessions 0", "MaxSessions 10")
    .replace("ForceCommand /usr/sbin/nologin", ""),
    "PermitTTY yes": lambda c: c.replace("PermitTTY no", "PermitTTY yes").replace("MaxSessions 0", "MaxSessions 10"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote")
    ap.add_argument("--control", action="store_true")
    a = ap.parse_args()
    if a.remote:
        for var in ("TUNNEL_KEY", "TUNNEL_CERT", "TUNNEL_KNOWN_HOSTS"):
            if not os.environ.get(var):
                print("FAIL UNCHECKED: %s is not set" % var)
                return 1
        desk = Desk(tempfile.mkdtemp(), a.remote, 2222, os.environ["TUNNEL_KNOWN_HOSTS"])
        desk.key = os.environ["TUNNEL_KEY"]
        return ladder(desk, False)
    echo_server()
    if a.control:
        bad = 0
        for name, weaken in WEAKENED.items():
            caught = local_run(weaken, quiet=True) != 0
            bad += not caught
            print("  %s weakened sshd: %s" % ("ok  " if caught else "FAIL", name))
        print("%d control(s) wrong" % bad)
        return 1 if bad else 0
    return local_run()


if __name__ == "__main__":
    sys.exit(main())
