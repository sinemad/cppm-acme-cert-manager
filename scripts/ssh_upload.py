"""ssh_upload.py — generic Linux SSH target: smoke test + certificate deploy.

Mirrors clearpass_upload.py's role for the "linux_ssh" target_type: push the
issued cert/key to a fixed remote directory (fullchain.pem / privkey.pem) and
run a configurable reload command, over plain `ssh`/`scp` (no paramiko — see
LINUX_SSH_TARGET_PLAN.md for why).

Host keys are TOFU-pinned per (ssh_host, ssh_port) the first time a connection
succeeds, in a dedicated known_hosts file under the servers.json directory —
shared across every server entry that points at the same host, since the pin
is a property of the target host, not of any one server config. Every
subsequent connection uses StrictHostKeyChecking=yes against that file, so a
host key that changes later is a hard connection failure, never silently
re-pinned.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

_SSH_CONNECT_TIMEOUT = 10
_SSH_COMMAND_TIMEOUT = 20
_PROBE_PREFIX = ".cppm_acme_probe_"

_SERVERS_DIR = Path(os.environ.get("SERVERS_FILE", "/data/certs/servers.json")).parent
_KNOWN_HOSTS_DIR = _SERVERS_DIR / "ssh_known_hosts"


def _safe_host_key(host: str, port: int) -> str:
    safe = re.sub(r"[^\w.\-]", "_", host).strip("._-") or "host"
    return f"{safe}_{port}"


def _known_hosts_path(host: str, port: int) -> Path:
    return _KNOWN_HOSTS_DIR / f"{_safe_host_key(host, port)}.known_hosts"


def _ensure_host_key_pinned(host: str, port: int) -> Optional[dict]:
    """Pin the host key via ssh-keyscan on first contact. Returns an error
    dict if scanning fails; None on success (including "already pinned")."""
    path = _known_hosts_path(host, port)
    if path.exists() and path.stat().st_size > 0:
        return None
    _KNOWN_HOSTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "-T", str(_SSH_CONNECT_TIMEOUT), host],
            capture_output=True, text=True, timeout=_SSH_CONNECT_TIMEOUT + 5,
        )
    except subprocess.TimeoutExpired:
        return {"status": "error",
                "message": f"Timed out scanning host key for {host}:{port}.",
                "remediation": [f"Verify {host}:{port} is reachable and accepting SSH connections."]}
    if not result.stdout.strip():
        return {"status": "error",
                "message": f"Could not retrieve a host key from {host}:{port} "
                            f"(ssh-keyscan returned nothing).",
                "remediation": [f"Verify {host}:{port} is reachable and running sshd.",
                                 result.stderr.strip() or "ssh-keyscan produced no error output."]}
    path.write_text(result.stdout, encoding="utf-8")
    path.chmod(0o600)
    return None


@contextmanager
def _temp_key_file(private_key: str):
    if not private_key.strip():
        yield None
        return
    key = private_key if private_key.endswith("\n") else private_key + "\n"
    tmp = tempfile.NamedTemporaryFile(mode="w", prefix="cppm_ssh_key_", delete=False)
    try:
        tmp.write(key)
        tmp.close()
        os.chmod(tmp.name, 0o600)
        yield tmp.name
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def _ssh_base_args(host: str, port: int, user: str, key_path: Optional[str]) -> list[str]:
    args = [
        "ssh",
        "-o", "BatchMode=yes" if key_path else "BatchMode=no",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
        "-o", f"UserKnownHostsFile={_known_hosts_path(host, port)}",
        "-o", "StrictHostKeyChecking=yes",
        "-p", str(port),
    ]
    if key_path:
        args += ["-i", key_path, "-o", "IdentitiesOnly=yes"]
    args.append(f"{user}@{host}")
    return args


def _run_remote(host: str, port: int, user: str, key_path: Optional[str],
                 password: str, command: str, timeout: int = _SSH_COMMAND_TIMEOUT):
    args = _ssh_base_args(host, port, user, key_path) + [command]
    if not key_path and password:
        args = ["sshpass", "-p", password] + args
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _scp_up(host: str, port: int, user: str, key_path: Optional[str],
            password: str, local_path: str, remote_path: str, timeout: int = 30):
    args = [
        "scp",
        "-o", "BatchMode=yes" if key_path else "BatchMode=no",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
        "-o", f"UserKnownHostsFile={_known_hosts_path(host, port)}",
        "-o", "StrictHostKeyChecking=yes",
        "-P", str(port),
    ]
    if key_path:
        args += ["-i", key_path, "-o", "IdentitiesOnly=yes"]
    if not key_path and password:
        args = ["sshpass", "-p", password] + args
    args += [local_path, f"{user}@{host}:{remote_path}"]
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _host_key_error(host: str, port: int, stderr: str) -> dict:
    path = _known_hosts_path(host, port)
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr or "Host key verification failed" in stderr:
        return {
            "status": "error",
            "message": f"SSH host key for {host}:{port} does not match the pinned key — "
                        f"this could mean the host was reinstalled, OR a man-in-the-middle attack.",
            "remediation": [
                "Do NOT proceed until you've confirmed this is expected (e.g. the host was "
                "rebuilt/reimaged on purpose).",
                f"If expected, remove the stale pin and let it re-pin on the next test: "
                f"rm {path}",
            ],
        }
    return {
        "status": "error",
        "message": f"SSH connection to {host}:{port} failed: {stderr.strip()[:300] or 'unknown error'}",
        "remediation": [
            f"Verify {host}:{port} is reachable and sshd is running.",
            "Check that the configured username, private key, or password are correct.",
        ],
    }


def test_ssh_target(entry: dict) -> dict:
    """Smoke test: verify the configured SSH credentials can read/write the
    remote certificate directory. Never runs reload_command — only a
    non-destructive `sudo -n -l` dry check if it looks like it needs sudo.

    Returns {"status": "ok"|"warn"|"error", "message": str,
             "remediation": [str, ...]} — remediation is only present when
    there's something to fix.
    """
    host = str(entry.get("ssh_host", "")).strip()
    user = str(entry.get("ssh_user", "")).strip()
    remote_dir = str(entry.get("remote_cert_dir", "")).strip()
    reload_command = str(entry.get("reload_command", "")).strip()
    private_key = str(entry.get("ssh_private_key", "") or "")
    password = str(entry.get("ssh_password", "") or "")
    try:
        port = int(entry.get("ssh_port") or 22)
    except (TypeError, ValueError):
        return {"status": "error", "message": "SSH port must be a number."}

    if not host or not user or not remote_dir:
        return {"status": "unknown", "message": "Not configured"}
    if not private_key.strip() and not password.strip():
        return {"status": "error", "message": "Either a private key or a password is required.",
                "remediation": ["Paste the SSH private key, or fall back to a password."]}

    pin_error = _ensure_host_key_pinned(host, port)
    if pin_error:
        return pin_error

    with _temp_key_file(private_key) as key_path:
        probe_name = f"{_PROBE_PREFIX}{os.getpid()}"
        remote_probe = f"{remote_dir.rstrip('/')}/{probe_name}"
        script = (
            f"test -d {shlex.quote(remote_dir)} || echo __NODIR__ && "
            f"(echo ok > {shlex.quote(remote_probe)} 2>/tmp/__cppm_err__ "
            f"|| (echo __WRITEFAIL__; cat /tmp/__cppm_err__ 2>/dev/null)) && "
            f"(cat {shlex.quote(remote_probe)} >/dev/null 2>&1 || echo __READFAIL__) && "
            f"(rm -f {shlex.quote(remote_probe)} || echo __DELETEFAIL__) && "
            f"echo __OK__"
        )
        try:
            result = _run_remote(host, port, user, key_path, password, script)
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": f"SSH command to {host} timed out.",
                    "remediation": ["Verify the host is reachable and not overloaded."]}
        except FileNotFoundError as exc:
            return {"status": "error",
                    "message": f"Required SSH tooling not available in this container: {exc}.",
                    "remediation": ["This is a container build issue, not a credentials issue."]}

        stderr = result.stderr or ""
        stdout = result.stdout or ""

        if result.returncode == 255:
            if "Permission denied" in stderr:
                return {
                    "status": "error",
                    "message": f"Authentication to {user}@{host} failed (permission denied).",
                    "remediation": [
                        f"Confirm the public key for this private key is in "
                        f"~{user}/.ssh/authorized_keys on {host} (or the password is correct).",
                        f"Test manually: ssh -p {port} {user}@{host}",
                    ],
                }
            return {"status": "error", **_host_key_error(host, port, stderr)}

        if "__NODIR__" in stdout:
            return {
                "status": "error",
                "message": f"Remote directory {remote_dir} does not exist on {host}.",
                "remediation": [f"sudo mkdir -p {remote_dir}",
                                 f"sudo chown {user}:{user} {remote_dir}",
                                 f"sudo chmod 750 {remote_dir}"],
            }
        if "__WRITEFAIL__" in stdout:
            return {
                "status": "error",
                "message": f"User '{user}' cannot write to {remote_dir} on {host}.",
                "remediation": [f"sudo chown {user}:{user} {remote_dir}",
                                 f"sudo chmod 750 {remote_dir}"],
            }
        if "__READFAIL__" in stdout:
            return {
                "status": "error",
                "message": f"User '{user}' cannot read back from {remote_dir} on {host}.",
                "remediation": [f"sudo chmod 750 {remote_dir}",
                                 f"sudo chown {user}:{user} {remote_dir}"],
            }
        if "__DELETEFAIL__" in stdout:
            return {
                "status": "warn",
                "message": f"Wrote and read a test file in {remote_dir} but could not delete it "
                            f"— deploys may leave stray files behind.",
                "remediation": [f"sudo chown {user}:{user} {remote_dir}",
                                 f"sudo chmod 750 {remote_dir}"],
            }
        if "__OK__" not in stdout:
            return {"status": "error",
                    "message": f"Unexpected response from {host}: {stdout.strip()[:200] or stderr.strip()[:200]}"}

        # Directory access is fine. If reload_command looks like it needs sudo,
        # dry-check (never actually run it — it can restart a live service).
        if reload_command.strip().startswith("sudo"):
            inner = reload_command.strip()[len("sudo"):].strip()
            try:
                check = _run_remote(host, port, user, key_path, password,
                                     f"sudo -n -l {inner} 2>&1")
            except subprocess.TimeoutExpired:
                check = None
            if check is None or check.returncode != 0:
                sudoers_line = f"{user} ALL=(root) NOPASSWD: {inner}"
                return {
                    "status": "warn",
                    "message": f"SSH and directory access OK, but '{user}' cannot run "
                                f"'{reload_command}' without a password — the deploy would "
                                f"stall waiting for sudo input.",
                    "remediation": [
                        f"On {host}, add a sudoers rule scoped to just this command:",
                        f"echo '{sudoers_line}' | sudo tee /etc/sudoers.d/cppm-acme-{user}",
                    ],
                }

        return {"status": "ok", "message": f"SSH connection and directory permissions OK on {host}."}


def deploy_to_ssh_target(env: dict) -> int:
    """Push fullchain/privkey to the remote host and run reload_command.

    Reads SERVER_CERT_DIR/<domain>.ecc.fullchain.cer + .ecc.key (linux_ssh
    targets always deploy the ECC cert — see LINUX_SSH_TARGET_PLAN.md).
    Returns a process-style exit code (0 = success) for the deploy hook.
    """
    import sys

    host = env.get("SSH_HOST", "").strip()
    user = env.get("SSH_USER", "").strip()
    remote_dir = env.get("REMOTE_CERT_DIR", "").strip()
    reload_command = env.get("RELOAD_COMMAND", "").strip()
    private_key = env.get("SSH_PRIVATE_KEY", "") or ""
    password = env.get("SSH_PASSWORD", "") or ""
    try:
        port = int(env.get("SSH_PORT") or 22)
    except (TypeError, ValueError):
        print(f"ERROR: invalid SSH_PORT {env.get('SSH_PORT')!r}", file=sys.stderr)
        return 1

    fullchain = env.get("LOCAL_FULLCHAIN", "")
    privkey = env.get("LOCAL_PRIVKEY", "")
    if not fullchain or not Path(fullchain).is_file():
        print(f"ERROR: fullchain not found: {fullchain}", file=sys.stderr)
        return 1
    if not privkey or not Path(privkey).is_file():
        print(f"ERROR: private key not found: {privkey}", file=sys.stderr)
        return 1

    pin_error = _ensure_host_key_pinned(host, port)
    if pin_error:
        print(f"ERROR: {pin_error['message']}", file=sys.stderr)
        return 1

    with _temp_key_file(private_key) as key_path:
        remote_full_tmp = f"{remote_dir.rstrip('/')}/.fullchain.pem.new"
        remote_key_tmp = f"{remote_dir.rstrip('/')}/.privkey.pem.new"
        remote_full = f"{remote_dir.rstrip('/')}/fullchain.pem"
        remote_key = f"{remote_dir.rstrip('/')}/privkey.pem"

        for local_path, remote_tmp in ((fullchain, remote_full_tmp), (privkey, remote_key_tmp)):
            try:
                r = _scp_up(host, port, user, key_path, password, local_path, remote_tmp)
            except subprocess.TimeoutExpired:
                print(f"ERROR: scp to {host} timed out", file=sys.stderr)
                return 1
            if r.returncode != 0:
                print(f"ERROR: scp {local_path} -> {host}:{remote_tmp} failed: {r.stderr}", file=sys.stderr)
                return 1

        move_cmd = (
            f"chmod 600 {shlex.quote(remote_key_tmp)} && "
            f"mv {shlex.quote(remote_full_tmp)} {shlex.quote(remote_full)} && "
            f"mv {shlex.quote(remote_key_tmp)} {shlex.quote(remote_key)}"
        )
        try:
            r = _run_remote(host, port, user, key_path, password, move_cmd)
        except subprocess.TimeoutExpired:
            print(f"ERROR: move command on {host} timed out", file=sys.stderr)
            return 1
        if r.returncode != 0:
            print(f"ERROR: could not move cert files into place on {host}: {r.stderr}", file=sys.stderr)
            return 1
        print(f"Deployed fullchain.pem/privkey.pem to {host}:{remote_dir}")

        if reload_command:
            try:
                r = _run_remote(host, port, user, key_path, password, reload_command, timeout=60)
            except subprocess.TimeoutExpired:
                print(f"ERROR: reload_command on {host} timed out", file=sys.stderr)
                return 1
            if r.returncode != 0:
                print(f"ERROR: reload_command failed (exit {r.returncode}): {r.stderr}", file=sys.stderr)
                return 1
            print(f"Reload command succeeded on {host}: {reload_command}")

    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or sys.argv[1] != "deploy":
        print("usage: ssh_upload.py deploy", file=sys.stderr)
        sys.exit(2)
    sys.exit(deploy_to_ssh_target(os.environ))
