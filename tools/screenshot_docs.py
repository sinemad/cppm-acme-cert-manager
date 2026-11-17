#!/usr/bin/env python3
"""
screenshot_docs.py - Regenerate docs/ui-*.png screenshots from sample data.

Spins up a throwaway container from the project's own Docker image, seeds it
with placeholder servers and an admin user (never real customer/lab data),
drives a headless browser through each documented page (empty-state checklist,
ClearPass and Linux SSH servers, Certificate Profiles, DNS Credentials), and
saves the resulting PNGs into docs/.

Requirements (one-time):
    pip install playwright
    playwright install chromium

Usage:
    python3 tools/screenshot_docs.py            # capture everything below
    python3 tools/screenshot_docs.py --keep      # leave the container running for inspection

The image must already be built (docker compose build, or docker build -t
cppm-acme-cert-manager:latest .) before running this script.
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

IMAGE = "cppm-acme-cert-manager:latest"
CONTAINER = "cppm-doc-shots"
HOST_PORT = 18080
ADMIN_USER = "admin"
ADMIN_PASS = "DocScreenshot123!"
DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"
VIEWPORT = {"width": 1440, "height": 900}

# Placeholder data only — never real server/credential values.
SAMPLE_DNS_CREDENTIALS = [
    ("cloudflare-example", "cloudflare", {"CF_Token": "sample-token-not-real"}),
    ("porkbun-example", "porkbun", {
        "PORKBUN_API_KEY": "sample-key-not-real",
        "PORKBUN_SECRET_API_KEY": "sample-secret-not-real",
    }),
]

_CLEARPASS_COMMON = {
    "cppm_client_id": "sample-api-client",
    "cppm_client_secret": "sample-not-a-real-secret",
    "cppm_callback_port": 8765,
    "acme_email": "admin@example.com",
    "dns_credential_id": "cloudflare-example",
    "cert_types": ["https_ecc", "https_rsa", "radius", "radsec"],
}

# (key, entry). Entries sharing a certificate_id form a Certificate Profile
# (the Profiles tab only lists explicit certificate_id values). add_server()
# copies the shared ACME/DNS fields from the first member, so only the first
# member of each profile needs them spelled out.
SAMPLE_SERVERS = [
    ("prod", {
        **_CLEARPASS_COMMON,
        "label": "Production ClearPass (Publisher)",
        "certificate_id": "clearpass-prod",
        "cppm_host": "clearpass.example.com",
        "domain": "clearpass.example.com",
        "acme_server": "letsencrypt",
    }),
    ("prod_sub", {
        **_CLEARPASS_COMMON,
        "label": "Production ClearPass (Subscriber)",
        "certificate_id": "clearpass-prod",
        "cppm_host": "clearpass-sub.example.com",
    }),
    ("lab", {
        **_CLEARPASS_COMMON,
        "label": "Lab ClearPass",
        "certificate_id": "clearpass-lab",
        "cppm_host": "clearpass-lab.example.com",
        "cppm_client_id": "sample-api-client-lab",
        "domain": "lab.example.com",
        "acme_server": "https://acme-staging-v02.api.letsencrypt.org/directory",
    }),
    # Linux SSH entries keep their type-specific fields under target_config.
    ("frigate", {
        "label": "Frigate NVR",
        "target_type": "linux_ssh",
        "certificate_id": "frigate",
        "domain": "frigate.example.com",
        "acme_email": "admin@example.com",
        "acme_server": "letsencrypt",
        "dns_credential_id": "porkbun-example",
        "target_config": {
            "ssh_host": "frigate.example.com",
            "ssh_port": "22",
            "ssh_user": "deploy",
            "remote_cert_dir": "/opt/frigate/certs",
            "reload_command": "",
            "services": ["Frigate", "Apache"],
            "ssh_private_key": "sample-not-a-real-private-key",
            "ssh_password": "",
        },
    }),
    ("proxy", {
        "label": "Edge Proxy",
        "target_type": "linux_ssh",
        "certificate_id": "frigate",
        "target_config": {
            "ssh_host": "proxy.example.com",
            "ssh_port": "22",
            "ssh_user": "deploy",
            "remote_cert_dir": "/etc/ssl/acme",
            "reload_command": "systemctl reload nginx",
            "services": ["nginx"],
            "ssh_private_key": "sample-not-a-real-private-key",
            "ssh_password": "",
        },
    }),
]

# Pages captured while the app has NO servers and NO DNS credentials, so the
# empty-state "Get started" checklist shows. (output filename, path)
EMPTY_PAGES = [
    ("ui-get-started.png", "/"),
]

# Pages captured after seeding. (output filename, path template); {key} in a
# template is replaced by the server ID of the SAMPLE_SERVERS entry with that
# key, e.g. "/settings/edit/{prod}".
PAGES = [
    ("ui-servers-list.png", "/settings"),
    ("ui-server-edit.png", "/settings/edit/{prod}"),
    ("ui-server-form-linux.png", "/settings/add?target_type=linux_ssh"),
    ("ui-server-edit-linux.png", "/settings/edit/{frigate}"),
    ("ui-profiles.png", "/settings/profiles"),
    ("ui-profile-edit.png", "/settings/profiles/edit/clearpass-prod"),
    ("ui-dns-credentials.png", "/settings/dns-credentials"),
]


def run(cmd, **kw):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def seed_py(statements: str) -> list:
    return [
        "docker", "exec", CONTAINER, "python3", "-c",
        "import sys; sys.path.insert(0, '/opt/cppm'); " + statements,
    ]


def wait_for_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true",
                         help="Leave the container running after capture")
    args = parser.parse_args()

    if shutil.which("docker") is None:
        print("docker is required on PATH.", file=sys.stderr)
        return 1

    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        print("playwright is required: pip install playwright && playwright install chromium",
              file=sys.stderr)
        return 1

    data_dir = Path(tempfile.mkdtemp(prefix="cppm-doc-shots-"))
    server_ids = {}

    try:
        run(["docker", "rm", "-f", CONTAINER],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass

    try:
        run([
            "docker", "run", "-d", "--name", CONTAINER,
            "-p", f"{HOST_PORT}:8080",
            "-v", f"{data_dir}:/data/certs",
            "-e", "STATUS_PORT=8080",
            IMAGE,
        ])

        wait_for_http(f"http://localhost:{HOST_PORT}/", timeout=30)

        run(seed_py(
            f"from auth_utils import save_user; "
            f"save_user({ADMIN_USER!r}, {ADMIN_PASS!r})"
        ))

        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport=VIEWPORT)
            page.goto(f"http://localhost:{HOST_PORT}/login")
            page.fill('input[name="username"]', ADMIN_USER)
            page.fill('input[name="password"]', ADMIN_PASS)
            page.click('button[type="submit"]')
            page.wait_for_load_state("networkidle")

            def shoot(filename, path):
                page.goto(f"http://localhost:{HOST_PORT}{path}")
                page.wait_for_load_state("networkidle")
                out = DOCS_DIR / filename
                page.screenshot(path=str(out), full_page=True)
                print(f"saved {out}")

            # 1) Empty state: nothing seeded yet, so the checklist shows.
            for filename, path in EMPTY_PAGES:
                shoot(filename, path)

            # 2) Seed DNS credentials, then servers (credentials must exist
            #    first because entries reference them by dns_credential_id).
            for cred_id, provider, creds in SAMPLE_DNS_CREDENTIALS:
                run(seed_py(
                    f"from config_utils import add_dns_credential; "
                    f"add_dns_credential({cred_id!r}, {provider!r}, {creds!r})"
                ))
            for key, entry in SAMPLE_SERVERS:
                result = run(seed_py(
                    f"from config_utils import add_server; "
                    f"print(add_server({entry!r}))"
                ), capture_output=True, text=True)
                server_ids[key] = result.stdout.strip().splitlines()[-1]

            # 3) Populated pages.
            for filename, path_tpl in PAGES:
                shoot(filename, path_tpl.format(**server_ids))

            browser.close()

    finally:
        if args.keep:
            print(f"Container '{CONTAINER}' left running on http://localhost:{HOST_PORT} "
                  f"(sign in as {ADMIN_USER}/{ADMIN_PASS}). Remove it with: docker rm -f {CONTAINER}")
        else:
            subprocess.run(["docker", "rm", "-f", CONTAINER],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.rmtree(data_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
