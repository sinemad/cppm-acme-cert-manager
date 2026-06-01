#!/usr/bin/env python3
"""
status_server.py – Read-only web status dashboard for cppm-acme-cert-manager.

Starts an HTTP server on STATUS_PORT (default 8080) that serves a single-page
dashboard showing certificate status, renewal schedule, provider config, and
a live activity log parsed from status.log.

Started as a background process by entrypoint.sh before exec supercronic.
"""

import datetime
import json
import os
import sys
import zoneinfo
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ── Configuration from environment ───────────────────────────────────────────
CERT_DIR     = Path(os.environ.get("CERT_DIR", "/data/certs"))
DOMAIN       = os.environ.get("DOMAIN", "unknown")
DNS_PROVIDER = os.environ.get("DNS_PROVIDER", "unknown")
ACME_SERVER  = os.environ.get("ACME_SERVER", "letsencrypt")
CPPM_HOST    = os.environ.get("CPPM_HOST", "unknown")
STATUS_PORT  = int(os.environ.get("STATUS_PORT", "8080"))
TZ_NAME      = os.environ.get("TZ", "UTC")
STATUS_LOG   = CERT_DIR / "status.log"


def _tz() -> datetime.tzinfo:
    try:
        return zoneinfo.ZoneInfo(TZ_NAME)
    except Exception:
        return datetime.timezone.utc


# ── Certificate parsing ───────────────────────────────────────────────────────

def parse_cert(path: Path) -> dict:
    """Read a PEM cert file and return a structured dict of its details."""
    if not path.exists():
        return {"exists": False}

    pem_bytes = path.read_bytes()
    result = {"exists": True, "pem": pem_bytes.decode("utf-8", errors="replace")}

    if not HAS_CRYPTOGRAPHY:
        return result

    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)

        # Dates — cryptography ≥42 has timezone-aware variants; fall back for older
        try:
            not_before = cert.not_valid_before_utc
            not_after  = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after  = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        now       = datetime.datetime.now(datetime.timezone.utc)
        days_left = (not_after - now).days

        # Subject CN
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = cert.subject.rfc4514_string()

        # Subject Alternative Names
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in san_ext.value]
        except Exception:
            pass

        # Issuer
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            issuer_cn = cert.issuer.rfc4514_string()
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            issuer_org = ""

        # Public key
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            key_type  = "ECDSA"
            key_size  = pub.key_size
            key_curve = pub.curve.name
        elif isinstance(pub, rsa.RSAPublicKey):
            key_type  = "RSA"
            key_size  = pub.key_size
            key_curve = None
        else:
            key_type  = type(pub).__name__
            key_size  = getattr(pub, "key_size", 0)
            key_curve = None

        result.update({
            "cn":         cn,
            "san":        sans,
            "issuer_cn":  issuer_cn,
            "issuer_org": issuer_org,
            "serial":     format(cert.serial_number, "x").upper(),
            "not_before": not_before.isoformat(),
            "not_after":  not_after.isoformat(),
            "days_left":  days_left,
            "key_type":   key_type,
            "key_size":   key_size,
            "key_curve":  key_curve,
        })

    except Exception as e:
        result["parse_error"] = str(e)

    return result


# ── Status log parsing ────────────────────────────────────────────────────────

def parse_log(max_entries: int = 40) -> list:
    """Return the last max_entries non-comment lines from status.log, newest first."""
    if not STATUS_LOG.exists():
        return []
    entries = []
    try:
        lines = STATUS_LOG.read_text(errors="replace").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|", 3)]
            if len(parts) == 4:
                entries.append({
                    "ts":       parts[0],
                    "level":    parts[1],
                    "category": parts[2],
                    "message":  parts[3],
                })
            if len(entries) >= max_entries:
                break
    except Exception:
        pass
    return entries


# ── Schedule calculation ──────────────────────────────────────────────────────

def next_check_info() -> dict:
    """Compute the next two renewal check times (02:00 and 14:00 container-local time)."""
    tz  = _tz()
    now = datetime.datetime.now(tz)

    candidates = []
    for day_offset in range(3):
        for hour in (2, 14):
            dt = datetime.datetime(
                now.year, now.month, now.day, hour, 0, 0, tzinfo=tz
            ) + datetime.timedelta(days=day_offset)
            if dt > now:
                candidates.append(dt)
    candidates.sort()

    if not candidates:
        return {}

    nxt   = candidates[0]
    delta = nxt - now
    secs  = int(delta.total_seconds())
    h, r  = divmod(secs, 3600)
    m     = r // 60
    until = f"{h}h {m}m" if h else f"{m}m"

    return {
        "next_dt":   nxt.isoformat(),
        "next_utc":  nxt.astimezone(datetime.timezone.utc).isoformat(),
        "until":     until,
        "schedule":  "02:00 and 14:00 daily",
        "threshold": "≤30 days remaining",
    }


# ── Status data builder ───────────────────────────────────────────────────────

def build_status() -> dict:
    tz = _tz()
    return {
        "domain":       DOMAIN,
        "dns_provider": DNS_PROVIDER,
        "acme_server":  ACME_SERVER,
        "cppm_host":    CPPM_HOST,
        "certs": {
            "ecc": parse_cert(CERT_DIR / f"{DOMAIN}.ecc.cer"),
            "rsa": parse_cert(CERT_DIR / f"{DOMAIN}.rsa.cer"),
        },
        "schedule": next_check_info(),
        "activity": parse_log(40),
        "server_time": datetime.datetime.now(tz).isoformat(),
    }


# ── Embedded HTML dashboard ───────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CPPM ACME Certificate Manager</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--card:#1e293b;--border:#334155;--border2:#475569;
  --accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--info:#818cf8;
  --text:#e2e8f0;--muted:#94a3b8;--subtle:#64748b;
  --radius:0.75rem;--shadow:0 4px 24px rgba(0,0,0,.4);
}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6;min-height:100vh}

.app{max-width:1200px;margin:0 auto;padding:1.5rem}

/* Header */
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding:1rem 1.5rem;background:var(--card);border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}
.hdr-left{display:flex;align-items:center;gap:1rem}
.hdr-logo{font-size:1rem;font-weight:700;color:var(--accent);letter-spacing:-.01em}
.hdr-domain{font-size:0.8rem;color:var(--muted);font-family:monospace;background:rgba(56,189,248,.08);padding:0.15rem 0.5rem;border-radius:4px;border:1px solid rgba(56,189,248,.15)}
.hdr-right{display:flex;align-items:center;gap:0.6rem;font-size:0.78rem;color:var(--subtle)}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--subtle);transition:background .3s}
.pulse.active{background:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.2)}

/* Grids */
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-bottom:1rem}
@media(max-width:700px){.grid-2{grid-template-columns:1fr}}

/* Generic card */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow)}
.card-title{font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:0.85rem}

/* Cert cards */
.cert-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow);border-left:3px solid var(--subtle);transition:border-color .3s}
.cert-card.ok{border-left-color:var(--ok)}
.cert-card.warn{border-left-color:var(--warn)}
.cert-card.danger{border-left-color:var(--danger)}

.cert-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.cert-title{font-size:0.85rem;font-weight:600}
.badge{font-size:0.68rem;padding:0.18rem 0.55rem;border-radius:999px;font-weight:600}
.badge-ok{background:rgba(34,197,94,.15);color:var(--ok)}
.badge-warn{background:rgba(245,158,11,.15);color:var(--warn)}
.badge-danger{background:rgba(239,68,68,.15);color:var(--danger)}
.badge-none{background:rgba(100,116,139,.12);color:var(--subtle)}

.days-num{font-size:2.8rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.days-num.ok{color:var(--ok)}
.days-num.warn{color:var(--warn)}
.days-num.danger{color:var(--danger)}
.days-num.none{color:var(--subtle)}
.days-label{font-size:0.72rem;color:var(--muted);margin-top:0.1rem}

.meta{margin-top:0.85rem;display:flex;flex-direction:column;gap:0.28rem}
.row{display:flex;gap:0.5rem;font-size:0.78rem}
.row .lbl{color:var(--muted);min-width:68px;flex-shrink:0}
.row .val{font-family:monospace;font-size:0.75rem;word-break:break-all}

.actions{margin-top:1rem}
.btn{display:inline-flex;align-items:center;gap:0.35rem;padding:0.38rem 0.85rem;border-radius:0.4rem;font-size:0.78rem;font-weight:500;border:none;cursor:pointer;transition:all .15s}
.btn-primary{background:rgba(56,189,248,.12);color:var(--accent);border:1px solid rgba(56,189,248,.25)}
.btn-primary:hover{background:rgba(56,189,248,.22)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border2)}
.btn-ghost:hover{color:var(--text);border-color:var(--muted)}

/* Schedule / config cards */
.big-val{font-size:1.6rem;font-weight:700;color:var(--accent);line-height:1}
.sub-val{font-size:0.78rem;color:var(--muted);margin-top:0.2rem;margin-bottom:0.85rem}

/* Activity log */
.log-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow)}
.log-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem}
.log-count{font-size:0.72rem;color:var(--subtle)}
.log-table{width:100%;border-collapse:collapse}
.log-table tr:hover td{background:rgba(255,255,255,.025)}
.log-table td{padding:0.32rem 0.5rem;border-bottom:1px solid rgba(51,65,85,.5);vertical-align:top}
.log-table td.ts{white-space:nowrap;color:var(--muted);font-family:monospace;font-size:0.72rem;padding-right:0.75rem}
.log-table td.lvl-cell{white-space:nowrap;width:64px}
.log-table td.cat{white-space:nowrap;color:var(--subtle);font-size:0.72rem;padding-right:0.75rem}
.log-table td.msg{color:var(--text);font-size:0.78rem}
.lvl{display:inline-block;padding:0.08rem 0.4rem;border-radius:3px;font-size:0.68rem;font-weight:600}
.lvl-ok{background:rgba(34,197,94,.13);color:var(--ok)}
.lvl-warn{background:rgba(245,158,11,.13);color:var(--warn)}
.lvl-failed{background:rgba(239,68,68,.13);color:var(--danger)}
.lvl-info{background:rgba(129,140,248,.13);color:var(--info)}

/* Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:200;display:none;align-items:center;justify-content:center;padding:1rem}
.overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:var(--radius);width:100%;max-width:680px;max-height:90vh;overflow-y:auto;box-shadow:0 24px 64px rgba(0,0,0,.7)}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card);z-index:1}
.modal-title{font-size:0.9rem;font-weight:600}
.modal-x{background:none;border:none;color:var(--muted);font-size:1.1rem;cursor:pointer;line-height:1;padding:0.25rem}
.modal-x:hover{color:var(--text)}
.modal-body{padding:1.25rem}

.detail-grid{display:grid;grid-template-columns:auto 1fr;gap:0.38rem 1rem;font-size:0.82rem;align-items:baseline}
.detail-grid .dl{color:var(--muted);white-space:nowrap}
.detail-grid .dv{font-family:monospace;font-size:0.78rem;word-break:break-all}

.pem-section{margin-top:1.25rem}
.pem-hdr{font-size:0.72rem;color:var(--muted);margin-bottom:0.4rem;display:flex;align-items:center;justify-content:space-between}
.pem-pre{background:#0a0f1a;border:1px solid var(--border);border-radius:0.4rem;padding:0.75rem;font-family:monospace;font-size:0.68rem;overflow-x:auto;white-space:pre;color:var(--muted);max-height:280px;overflow-y:auto;line-height:1.5}

.empty{text-align:center;padding:2.5rem;color:var(--subtle);font-size:0.85rem}
</style>
</head>
<body>
<div class="app">

<div class="hdr">
  <div class="hdr-left">
    <span class="hdr-logo">ClearPass Cert Manager</span>
    <span class="hdr-domain" id="hdr-domain">&hellip;</span>
  </div>
  <div class="hdr-right">
    <span class="pulse" id="pulse"></span>
    <span id="last-updated">Loading&hellip;</span>
  </div>
</div>

<div class="grid-2" id="cert-cards"></div>
<div class="grid-2" id="info-cards"></div>

<div class="log-card">
  <div class="log-hdr">
    <span class="card-title" style="margin:0">Activity Log</span>
    <span class="log-count" id="log-count"></span>
  </div>
  <table class="log-table">
    <tbody id="log-body">
      <tr><td colspan="4"><div class="empty">Loading&hellip;</div></td></tr>
    </tbody>
  </table>
</div>

</div><!-- .app -->

<!-- Certificate detail modal -->
<div class="overlay" id="overlay" onclick="overlayClick(event)">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-title" id="modal-title">Certificate Details</span>
      <button class="modal-x" onclick="closeModal()">&#x2715;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<script>
var REFRESH_MS = 30000;
var _certData = {ecc: null, rsa: null};

function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function cls(days) {
  if (days == null) return 'none';
  if (days > 30)   return 'ok';
  if (days > 14)   return 'warn';
  return 'danger';
}

function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'}); }
  catch(e) { return iso; }
}

function fmtDT(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-US',{
      year:'numeric',month:'short',day:'numeric',
      hour:'2-digit',minute:'2-digit',timeZoneName:'short'
    });
  } catch(e) { return iso; }
}

function dnsLabel(p) {
  var m = {cloudflare:'Cloudflare',cf:'Cloudflare',porkbun:'Porkbun',
    route53:'AWS Route53',aws:'AWS Route53',r53:'AWS Route53',
    digitalocean:'DigitalOcean',do:'DigitalOcean',godaddy:'GoDaddy',gd:'GoDaddy'};
  return m[p] || p;
}

function caLabel(s) {
  var m = {letsencrypt:"Let's Encrypt",letsencrypt_test:"Let's Encrypt (Staging)",
    zerossl:'ZeroSSL',buypass:'Buypass'};
  return m[s] || s;
}

function lvlBadge(l) {
  var c = {OK:'lvl-ok',WARN:'lvl-warn',FAILED:'lvl-failed',INFO:'lvl-info'}[l] || 'lvl-info';
  return '<span class="lvl '+c+'">'+esc(l)+'</span>';
}

function keyLabel(cert) {
  if (!cert.key_type) return '—';
  if (cert.key_type === 'ECDSA' && cert.key_curve) return cert.key_type+' ('+cert.key_curve+')';
  if (cert.key_size) return cert.key_type+' '+cert.key_size+'-bit';
  return cert.key_type;
}

function renderCertCard(cert, label, service, key) {
  if (!cert.exists) {
    return '<div class="cert-card">'
      +'<div class="cert-header"><span class="cert-title">'+esc(label)+'</span>'
      +'<span class="badge badge-none">Not Found</span></div>'
      +'<div class="days-num none">—</div>'
      +'<div class="days-label">days remaining</div>'
      +'<div class="meta"><div class="row"><span class="lbl">Service</span>'
      +'<span class="val">'+esc(service)+'</span></div></div></div>';
  }
  var d    = cert.days_left;
  var c    = cls(d);
  var slbl = c==='ok'?'Valid':c==='warn'?'Expiring Soon':c==='danger'?'Critical':'Unknown';
  var bCls = 'badge-'+c;
  return '<div class="cert-card '+c+'">'
    +'<div class="cert-header"><span class="cert-title">'+esc(label)+'</span>'
    +'<span class="badge '+bCls+'">'+slbl+'</span></div>'
    +'<div class="days-num '+c+'">'+(d!=null?d:'—')+'</div>'
    +'<div class="days-label">days remaining</div>'
    +'<div class="meta">'
    +'<div class="row"><span class="lbl">Expires</span><span class="val">'+fmtDate(cert.not_after)+'</span></div>'
    +'<div class="row"><span class="lbl">Issued</span><span class="val">'+fmtDate(cert.not_before)+'</span></div>'
    +'<div class="row"><span class="lbl">Issuer</span><span class="val">'+esc(cert.issuer_cn||'—')+'</span></div>'
    +'<div class="row"><span class="lbl">Key</span><span class="val">'+esc(keyLabel(cert))+'</span></div>'
    +'<div class="row"><span class="lbl">Service</span><span class="val">'+esc(service)+'</span></div>'
    +'</div>'
    +'<div class="actions"><button class="btn btn-primary" data-key="'+key+'" onclick="showCert(this.dataset.key)">View Details</button></div>'
    +'</div>';
}

function renderInfoCards(data) {
  var sc = data.schedule || {};
  var sched = '<div class="card">'
    +'<div class="card-title">Renewal Schedule</div>'
    +'<div class="big-val">'+esc(sc.until||'—')+'</div>'
    +'<div class="sub-val">until next check</div>'
    +'<div class="meta">'
    +'<div class="row"><span class="lbl">Next check</span><span class="val">'+esc(fmtDT(sc.next_dt))+'</span></div>'
    +'<div class="row"><span class="lbl">Schedule</span><span class="val">'+esc(sc.schedule||'—')+'</span></div>'
    +'<div class="row"><span class="lbl">Renews at</span><span class="val">'+esc(sc.threshold||'—')+'</span></div>'
    +'</div></div>';

  var cfg = '<div class="card">'
    +'<div class="card-title">Configuration</div>'
    +'<div class="meta">'
    +'<div class="row"><span class="lbl">Domain</span><span class="val">'+esc(data.domain)+'</span></div>'
    +'<div class="row"><span class="lbl">DNS</span><span class="val">'+esc(dnsLabel(data.dns_provider))+'</span></div>'
    +'<div class="row"><span class="lbl">CA</span><span class="val">'+esc(caLabel(data.acme_server))+'</span></div>'
    +'<div class="row"><span class="lbl">ClearPass</span><span class="val">'+esc(data.cppm_host)+'</span></div>'
    +'</div></div>';

  return sched + cfg;
}

function renderLog(activity) {
  if (!activity || !activity.length)
    return '<tr><td colspan="4"><div class="empty">No activity recorded yet.</div></td></tr>';
  return activity.map(function(e) {
    return '<tr>'
      +'<td class="ts">'+esc(e.ts)+'</td>'
      +'<td class="lvl-cell">'+lvlBadge(e.level)+'</td>'
      +'<td class="cat">'+esc(e.category)+'</td>'
      +'<td class="msg">'+esc(e.message)+'</td>'
      +'</tr>';
  }).join('');
}

function render(data) {
  document.getElementById('hdr-domain').textContent = data.domain || '—';
  document.getElementById('last-updated').textContent =
    'Updated ' + new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});

  var ecc = (data.certs && data.certs.ecc) || {exists:false};
  var rsa = (data.certs && data.certs.rsa) || {exists:false};
  _certData.ecc = ecc;
  _certData.rsa = rsa;
  document.getElementById('cert-cards').innerHTML =
    renderCertCard(ecc, 'ECC Certificate', 'HTTPS(ECC)', 'ecc') +
    renderCertCard(rsa, 'RSA Certificate', 'RADIUS', 'rsa');

  document.getElementById('info-cards').innerHTML = renderInfoCards(data);

  document.getElementById('log-body').innerHTML = renderLog(data.activity);
  var cnt = (data.activity || []).length;
  document.getElementById('log-count').textContent = cnt + ' event'+(cnt!==1?'s':'');
}

async function loadStatus() {
  var pulse = document.getElementById('pulse');
  pulse.classList.add('active');
  try {
    var res = await fetch('/api/status');
    if (!res.ok) throw new Error('HTTP '+res.status);
    var data = await res.json();
    render(data);
  } catch(e) {
    document.getElementById('last-updated').textContent = 'Error: '+e.message;
  } finally {
    setTimeout(function(){ pulse.classList.remove('active'); }, 800);
  }
}

setInterval(loadStatus, REFRESH_MS);
loadStatus();

function showCert(key) {
  var labels = {ecc: 'ECC Certificate', rsa: 'RSA Certificate'};
  showModal(_certData[key] || {exists: false}, labels[key] || key);
}

/* Modal */
function showModal(cert, label) {
  var kl = keyLabel(cert);
  var sans = (cert.san || []).join(', ') || '—';
  var serial = cert.serial
    ? (cert.serial.match(/.{1,2}/g)||[cert.serial]).join(':')
    : '—';
  var issuer = [cert.issuer_cn, cert.issuer_org].filter(Boolean).join(' / ') || '—';

  var html = '<div class="detail-grid">'
    +'<span class="dl">Subject CN</span><span class="dv">'+esc(cert.cn||'—')+'</span>'
    +'<span class="dl">SANs</span><span class="dv">'+esc(sans)+'</span>'
    +'<span class="dl">Issuer</span><span class="dv">'+esc(issuer)+'</span>'
    +'<span class="dl">Serial</span><span class="dv">'+esc(serial)+'</span>'
    +'<span class="dl">Key</span><span class="dv">'+esc(kl)+'</span>'
    +'<span class="dl">Valid From</span><span class="dv">'+esc(fmtDT(cert.not_before))+'</span>'
    +'<span class="dl">Valid Until</span><span class="dv">'+esc(fmtDT(cert.not_after))+'</span>'
    +'<span class="dl">Days Left</span><span class="dv">'+(cert.days_left!=null?cert.days_left+' days':'—')+'</span>'
    +'</div>';

  if (cert.pem) {
    html += '<div class="pem-section">'
      +'<div class="pem-hdr"><span>Public Certificate (PEM)</span>'
      +'<button class="btn btn-ghost" style="font-size:0.72rem;padding:0.2rem 0.6rem" onclick="copyPEM()">Copy</button></div>'
      +'<pre class="pem-pre" id="pem-pre">'+esc(cert.pem)+'</pre>'
      +'</div>';
  }

  document.getElementById('modal-title').textContent = label + ' Details';
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('overlay').classList.remove('open');
}

function overlayClick(e) {
  if (e.target === document.getElementById('overlay')) closeModal();
}

function copyPEM() {
  var pre = document.getElementById('pem-pre');
  if (!pre) return;
  var btn = pre.closest('.pem-section').querySelector('button');
  navigator.clipboard.writeText(pre.textContent).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function(){ btn.textContent = orig; }, 2000);
  }).catch(function() {
    var r = document.createRange();
    r.selectNode(pre);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
}

document.addEventListener('keydown', function(e){ if(e.key==='Escape') closeModal(); });
</script>
</body>
</html>"""


# ── HTTP request handler ──────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/status":
            try:
                data = build_status()
                body = json.dumps(data, default=str).encode("utf-8")
                self.send_response(200)
            except Exception as e:
                body = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress per-request logs; they would flood container stdout


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[status_server] Starting on 0.0.0.0:{STATUS_PORT}", flush=True)
    if not HAS_CRYPTOGRAPHY:
        print(
            "[status_server] WARNING: cryptography library not installed – "
            "certificate details will be limited to raw PEM display",
            file=sys.stderr, flush=True,
        )
    server = HTTPServer(("0.0.0.0", STATUS_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
