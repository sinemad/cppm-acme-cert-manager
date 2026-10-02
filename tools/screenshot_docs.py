#!/usr/bin/env python3
"""
screenshot_docs.py - Regenerate docs/ui-*.png screenshots from sample data.

Spins up a throwaway container from the project's own Docker image, seeds it
with placeholder servers and an admin user (never real customer/lab data),
drives a headless browser through each documented page, and saves the
resulting PNGs over the existing files in docs/.

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
SAMPLE_SERVERS = [
    {
        "label": "Production ClearPass",
        "cppm_host": "clearpass.example.com",
        "cppm_client_id": "sample-api-client",
        "cppm_client_secret": "sample-not-a-real-secret",
        "cppm_callback_port": 8765,
        "domain": "clearpass.example.com",
        "acme_email": "admin@example.com",
        "acme_server": "letsencrypt",
        "dns_provider": "cloudflare",
        "dns_credentials": {"CLOUDFLARE_API_TOKEN": "sample-token-not-real"},
        "cert_types": ["https_ecc", "https_rsa", "radius", "radsec"],
    },
    {
        "label": "Lab ClearPass",
        "cppm_host": "clearpass-lab.example.com",
        "cppm_client_id": "sample-api-client-lab",
        "cppm_client_secret": "sample-not-a-real-secret",
        "cppm_callback_port": 8765,
        "domain": "lab.example.com",
        "acme_email": "admin@example.com",
        "acme_server": "letsencrypt_test",
        "dns_provider": "cloudflare",
        "dns_credentials": {"CLOUDFLARE_API_TOKEN": "sample-token-not-real"},
        "cert_types": ["https_ecc", "https_rsa", "radius", "radsec"],
    },
]

# Each entry: (output filename, path to visit, optional server index to
# resolve into /settings/edit/<id> etc.)
PAGES = [
    ("ui-servers-list.png", "/settings", None),
    ("ui-server-edit.png", "/settings/edit/{id}", 0),
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
    server_ids = []

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

        for entry in SAMPLE_SERVERS:
            result = run(seed_py(
                f"from config_utils import add_server; "
                f"print(add_server({entry!r}))"
            ), capture_output=True, text=True)
            server_ids.append(result.stdout.strip().splitlines()[-1])

        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport=VIEWPORT)
            page.goto(f"http://localhost:{HOST_PORT}/login")
            page.fill('input[name="username"]', ADMIN_USER)
            page.fill('input[name="password"]', ADMIN_PASS)
            page.click('button[type="submit"]')
            page.wait_for_load_state("networkidle")

            for filename, path_tpl, server_idx in PAGES:
                path = path_tpl.format(id=server_ids[server_idx]) if server_idx is not None else path_tpl
                page.goto(f"http://localhost:{HOST_PORT}{path}")
                page.wait_for_load_state("networkidle")
                out = DOCS_DIR / filename
                page.screenshot(path=str(out), full_page=True)
                print(f"saved {out}")

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
