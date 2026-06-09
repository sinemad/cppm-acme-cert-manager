#!/usr/bin/env python3
"""
notify.py — Send notifications for cert/upload events.

Can be imported or called as a CLI:
    python3 notify.py --server-id <id> --event <event> --message <text> [--status ok|warn|failed]

Supported events:
    cert_issued     New certificates issued or renewed
    upload_success  ClearPass upload succeeded
    upload_failed   ClearPass upload failed
    cert_expiry     Certificate expiring within threshold
    acme_error      ACME or DNS provider error

Supported channel types:
    slack       Slack incoming webhook
    discord     Discord webhook
    teams       Microsoft Teams incoming webhook
    webhook     Generic HTTP POST/GET
    email       SMTP email
"""

import argparse
import datetime
import json
import logging
import os
import smtplib
import ssl
import sys
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

_log = logging.getLogger("notify")

# ── Colours / icons per status ────────────────────────────────────────────────

_STATUS_COLOR = {
    "ok":     {"slack": "good",    "hex": "#22c55e", "discord": 0x22C55E, "teams": "00b050"},
    "warn":   {"slack": "warning", "hex": "#f59e0b", "discord": 0xF59E0B, "teams": "ffc000"},
    "failed": {"slack": "danger",  "hex": "#ef4444", "discord": 0xEF4444, "teams": "ff0000"},
}
_STATUS_ICON = {"ok": "✅", "warn": "⚠️", "failed": "❌"}

_EVENT_LABEL = {
    "cert_issued":    "Certificate Issued",
    "upload_success": "Upload Succeeded",
    "upload_failed":  "Upload Failed",
    "cert_expiry":    "Certificate Expiring Soon",
    "acme_error":     "ACME / DNS Error",
}


def _status_for_event(event: str) -> str:
    if event in ("upload_failed", "acme_error"):
        return "failed"
    if event == "cert_expiry":
        return "warn"
    return "ok"


# ── Channel senders ───────────────────────────────────────────────────────────

def _http_post(url: str, payload: dict, headers: dict = None) -> None:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data,
                                   headers={"Content-Type": "application/json",
                                            **(headers or {})},
                                   method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status not in range(200, 300):
            raise RuntimeError(f"HTTP {resp.status}")


def _send_slack(channel: dict, server_label: str, event: str,
                message: str, status: str) -> None:
    url    = channel.get("webhook_url", "")
    color  = _STATUS_COLOR.get(status, _STATUS_COLOR["ok"])["slack"]
    title  = f"[{server_label}] {_EVENT_LABEL.get(event, event)}"
    _http_post(url, {
        "attachments": [{
            "color":    color,
            "title":    title,
            "text":     message,
            "footer":   "ClearPass ACME Certificate Manager",
            "ts":       int(datetime.datetime.now().timestamp()),
        }],
    })


def _send_discord(channel: dict, server_label: str, event: str,
                  message: str, status: str) -> None:
    url   = channel.get("webhook_url", "")
    color = _STATUS_COLOR.get(status, _STATUS_COLOR["ok"])["discord"]
    title = f"{_STATUS_ICON.get(status, '')} [{server_label}] {_EVENT_LABEL.get(event, event)}"
    _http_post(url, {
        "embeds": [{
            "title":       title,
            "description": message,
            "color":       color,
            "footer":      {"text": "ClearPass ACME Certificate Manager"},
            "timestamp":   datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }],
    })


def _send_teams(channel: dict, server_label: str, event: str,
                message: str, status: str) -> None:
    url   = channel.get("webhook_url", "")
    color = _STATUS_COLOR.get(status, _STATUS_COLOR["ok"])["teams"]
    title = f"{_STATUS_ICON.get(status, '')} [{server_label}] {_EVENT_LABEL.get(event, event)}"
    _http_post(url, {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": color,
        "summary":    title,
        "sections":   [{"activityTitle": title, "activityText": message, "markdown": True}],
    })


def _send_webhook(channel: dict, server_label: str, event: str,
                  message: str, status: str) -> None:
    url     = channel.get("url", "")
    method  = (channel.get("method") or "POST").upper()
    extra_headers = {}
    raw_headers = channel.get("headers") or {}
    if isinstance(raw_headers, dict):
        extra_headers = raw_headers
    elif isinstance(raw_headers, str):
        for line in raw_headers.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                extra_headers[k.strip()] = v.strip()

    payload = {
        "server":    server_label,
        "event":     event,
        "status":    status,
        "message":   message,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if method == "GET":
        import urllib.parse
        qs  = urllib.parse.urlencode(payload)
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(f"{url}{sep}{qs}",
                                      headers={"Content-Type": "application/json",
                                               **extra_headers},
                                      method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in range(200, 300):
                raise RuntimeError(f"HTTP {resp.status}")
    else:
        _http_post(url, payload, headers=extra_headers)


def _send_email(channel: dict, server_label: str, event: str,
                message: str, status: str) -> None:
    smtp_host = channel.get("smtp_host", "")
    smtp_port = int(channel.get("smtp_port") or 587)
    smtp_user = channel.get("smtp_user", "")
    smtp_pass = channel.get("smtp_pass", "")
    smtp_tls  = bool(channel.get("smtp_tls", True))
    from_addr = channel.get("from_addr") or smtp_user
    to_addrs  = channel.get("to") or []
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.replace(",", "\n").splitlines() if a.strip()]

    if not smtp_host or not to_addrs:
        raise ValueError("Email channel missing smtp_host or to address")

    icon    = _STATUS_ICON.get(status, "")
    subject = f"{icon} [CPPM ACME] [{server_label}] {_EVENT_LABEL.get(event, event)}"
    body    = (f"ClearPass ACME Certificate Manager\n"
               f"{'─' * 48}\n"
               f"Server : {server_label}\n"
               f"Event  : {_EVENT_LABEL.get(event, event)}\n"
               f"Status : {status.upper()}\n"
               f"Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
               f"{'─' * 48}\n\n"
               f"{message}\n")

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)

    ctx = ssl.create_default_context()
    if smtp_tls and smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=15) as s:
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, to_addrs, msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
            if smtp_tls:
                s.starttls(context=ctx)
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, to_addrs, msg.as_string())


_SENDERS = {
    "slack":   _send_slack,
    "discord": _send_discord,
    "teams":   _send_teams,
    "webhook": _send_webhook,
    "email":   _send_email,
}


# ── Public API ────────────────────────────────────────────────────────────────

def send_notification(server_id: str, event: str, message: str,
                      status: str = "") -> list[str]:
    """Send notifications for *event* to all matching channels for *server_id*.

    Returns a list of error strings (empty on full success).
    """
    from config_utils import get_server, get_server_notifications

    server = get_server(server_id)
    if not server:
        return [f"server {server_id!r} not found"]

    server_label = server.get("label") or server.get("cppm_host", server_id)
    notif_cfg    = get_server_notifications(server_id)
    channels     = notif_cfg.get("channels") or []

    if not status:
        status = _status_for_event(event)

    errors = []
    for ch in channels:
        if not ch.get("enabled", True):
            continue
        subscribed = ch.get("events") or []
        if event not in subscribed:
            continue
        ch_type = ch.get("type", "")
        sender  = _SENDERS.get(ch_type)
        if not sender:
            errors.append(f"unknown channel type {ch_type!r}")
            continue
        ch_name = ch.get("name") or ch_type
        try:
            sender(ch, server_label, event, message, status)
            _log.debug("notify: sent %s → %s/%s", event, ch_type, ch_name)
        except Exception as exc:
            err = f"channel {ch_name!r} ({ch_type}): {exc}"
            _log.warning("notify: %s", err)
            errors.append(err)

    return errors


def send_test(server_id: str, channel_id: str) -> tuple[bool, str]:
    """Send a test notification to a single channel. Returns (ok, message)."""
    from config_utils import get_server, get_server_notifications

    server = get_server(server_id)
    if not server:
        return False, f"Server {server_id!r} not found"

    server_label = server.get("label") or server.get("cppm_host", server_id)
    notif_cfg    = get_server_notifications(server_id)
    channels     = notif_cfg.get("channels") or []

    ch = next((c for c in channels if c.get("id") == channel_id), None)
    if not ch:
        return False, f"Channel {channel_id!r} not found"

    ch_type = ch.get("type", "")
    sender  = _SENDERS.get(ch_type)
    if not sender:
        return False, f"Unknown channel type {ch_type!r}"

    try:
        sender(ch, server_label, "upload_success",
               "This is a test notification from ClearPass ACME Certificate Manager.", "ok")
        return True, "Test notification sent successfully."
    except Exception as exc:
        return False, f"Send failed: {exc}"


# ── CLI entry point ───────────────────────────────────────────────────────────

def _main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Send CPPM ACME notifications")
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--event",     required=True,
                        choices=list(_EVENT_LABEL.keys()))
    parser.add_argument("--message",   required=True)
    parser.add_argument("--status",    default="",
                        choices=["", "ok", "warn", "failed"])
    args = parser.parse_args()

    errors = send_notification(args.server_id, args.event, args.message, args.status)
    if errors:
        for e in errors:
            print(f"WARN: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
