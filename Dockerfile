FROM alpine:3.19

ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="ClearPass ACME Certificate Manager" \
      org.opencontainers.image.description="Automated TLS certificate management for Aruba ClearPass Policy Manager via acme.sh DNS-01" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      maintainer="Network Engineering"

# ── System packages ───────────────────────────────────────────────────────────
RUN apk add --no-cache \
    bash \
    curl \
    git \
    openssl \
    python3 \
    py3-pip \
    py3-cryptography \
    py3-bcrypt \
    tzdata \
    socat \
    bind-tools \
    jq \
    ca-certificates \
    && update-ca-certificates

# Install supercronic – a container-native cron runner that does not
# require setpgid() or any elevated privileges, unlike dcron/busybox crond.
# Version pinned for reproducibility.
# Check latest releases: https://github.com/aptible/supercronic/releases
ENV SUPERCRONIC_VERSION=0.2.33
RUN curl -fsSL \
    "https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64" \
    -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic \
    && echo "supercronic installed: $(/usr/local/bin/supercronic --version 2>&1)"

# ── Python dependencies ───────────────────────────────────────────────────────
# Pin versions to prevent a breaking upstream release from silently
# breaking the container on rebuild.
# requests 2.32.x is the latest stable as of the image authoring date.
# urllib3 2.2.x is compatible with requests 2.32.x.
# requests and urllib3 are required by pyclearpass.
# pyclearpass is the official Aruba SDK for the ClearPass REST API.
# Version pinned for reproducibility.
RUN pip3 install --no-cache-dir --break-system-packages \
    "pyclearpass==1.0.8" \
    "requests==2.32.3" \
    "urllib3==2.2.3"

# ── Install acme.sh ───────────────────────────────────────────────────────────
# Clone the full repo (--depth 1) so all dnsapi/ scripts are available.
# We manually copy files into /opt/acme-seed/ rather than using acme.sh --install
# because --install requires CWD to contain acme.sh, which is not guaranteed
# in a Docker RUN layer.
RUN git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /opt/acme-src \
    # Patch the shebang FIRST, before any copies are made.
    # acme.sh calls itself internally using the path in LE_WORKING_DIR
    # (/data/certs/.acme-state/acme.sh), which is seeded from /opt/acme-seed/acme.sh.
    # If only /usr/local/bin/acme.sh is patched, the seed copy still runs under
    # Alpine ash, producing 'sh: DEBUG: out of range' errors on every invocation.
    # Patching the source before all copies ensures every code path uses bash.
    && sed -i '1s|#!/usr/bin/env sh|#!/usr/bin/env bash|' /opt/acme-src/acme.sh \
    # Install patched binary at stable system path
    && cp /opt/acme-src/acme.sh /usr/local/bin/acme.sh \
    && chmod +x /usr/local/bin/acme.sh \
    # Assemble seed directory from the patched source
    && mkdir -p /opt/acme-seed/dnsapi \
               /opt/acme-seed/deploy \
               /opt/acme-seed/notify \
    && cp /opt/acme-src/acme.sh      /opt/acme-seed/acme.sh \
    && cp /opt/acme-src/dnsapi/*.sh  /opt/acme-seed/dnsapi/ \
    && cp /opt/acme-src/deploy/*.sh  /opt/acme-seed/deploy/ \
    && cp /opt/acme-src/notify/*.sh  /opt/acme-seed/notify/ \
    # Patch every dnsapi, deploy, and notify script to use bash.
    # These are called by acme.sh during DNS challenges and cert hooks.
    # Without this patch they run under Alpine ash and may fail on bash-only syntax.
    && find /opt/acme-seed/dnsapi /opt/acme-seed/deploy /opt/acme-seed/notify \
            -name '*.sh' \
            -exec sed -i '1s|#!/usr/bin/env sh|#!/usr/bin/env bash|' {} \; \
    && touch /opt/acme-seed/account.conf \
    && test -f /opt/acme-seed/dnsapi/dns_cf.sh \
        || { echo "ERROR: dns_cf.sh missing from seed"; exit 1; } \
    # Confirm both copies have the bash shebang
    && head -1 /usr/local/bin/acme.sh \
    && head -1 /opt/acme-seed/acme.sh \
    && echo "acme.sh $(/usr/local/bin/acme.sh --version 2>&1 | head -1)" \
    && echo "dnsapi scripts bundled: $(ls /opt/acme-seed/dnsapi/ | wc -l)" \
    && rm -rf /opt/acme-src

# ── Bundle Let's Encrypt CA certificates ─────────────────────────────────────
# Downloaded at build time so the running container never needs letsencrypt.org.
# Roots: ISRG Root X1 (RSA) and X2 (ECDSA) — permanent, never change.
# Intermediates: Let's Encrypt rotates these periodically (roughly every 90 days).
#   Confirmed batches: 2024 → E5/E6 (ECDSA), R10/R11 (RSA)
#                      2024 → E7/E8/E9/E10 (ECDSA), R12/R13/R14 (RSA)
# Best-effort block below attempts all known intermediates across 2024 and 2025
# paths; any that do not exist yet are silently skipped. clearpass_upload.py also
# reads the actual .ca.cer chains from issued certs and uploads any missing
# intermediates at runtime, so the bundle is a warm-start optimisation only.
RUN mkdir -p /opt/cppm/acme-ca-certs \
    \
    # ── Roots (stable, always required) ───────────────────────────────────────
    && curl -fsSL https://letsencrypt.org/certs/isrgrootx1.pem \
            -o /opt/cppm/acme-ca-certs/isrg-root-x1.pem \
    && curl -fsSL https://letsencrypt.org/certs/isrg-root-x2.pem \
            -o /opt/cppm/acme-ca-certs/isrg-root-x2.pem \
    \
    # ── 2024 batch intermediates (confirmed) ───────────────────────────────────
    && curl -fsSL https://letsencrypt.org/certs/2024/e5.pem \
            -o /opt/cppm/acme-ca-certs/lets-encrypt-e5.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/e6.pem \
            -o /opt/cppm/acme-ca-certs/lets-encrypt-e6.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/r10.pem \
            -o /opt/cppm/acme-ca-certs/lets-encrypt-r10.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/r11.pem \
            -o /opt/cppm/acme-ca-certs/lets-encrypt-r11.pem \
    \
    # ── Additional intermediates (best-effort — skipped if not yet published) ──
    # Tries 2024 first, then 2025, for each intermediate name.
    # A cert is kept only if openssl can parse it; invalid/missing downloads are removed.
    && for name in e7 e8 e9 e10 r12 r13 r14; do \
           fname="lets-encrypt-${name}.pem"; \
           dest="/opt/cppm/acme-ca-certs/${fname}"; \
           for year in 2024 2025; do \
               url="https://letsencrypt.org/certs/${year}/${name}.pem"; \
               if curl -fsSL --max-time 15 "${url}" -o "${dest}.tmp" 2>/dev/null \
                  && openssl x509 -noout -subject -in "${dest}.tmp" >/dev/null 2>&1; then \
                   mv "${dest}.tmp" "${dest}"; \
                   echo "  Downloaded: ${fname} (${year})"; \
                   break; \
               fi; \
               rm -f "${dest}.tmp"; \
           done; \
       done \
    \
    # ── Validate every cert that was successfully downloaded ───────────────────
    && echo "Validating bundled LE certs..." \
    && for pem in /opt/cppm/acme-ca-certs/*.pem; do \
           subj=$(openssl x509 -noout -subject -in "$pem" 2>&1) \
           && echo "  OK: $(basename $pem) -> $subj" \
           || { echo "ERROR: invalid PEM: $pem"; exit 1; }; \
       done \
    && echo "Bundled $(ls /opt/cppm/acme-ca-certs/*.pem | wc -l) ACME CA certs."

# ── Copy application scripts ──────────────────────────────────────────────────
RUN mkdir -p /opt/cppm
COPY scripts/ /opt/cppm/
COPY VERSION  /opt/cppm/VERSION
COPY config/crontab /etc/crontabs/root
# Stamp build time — readable by status_server.py for display in the UI footer
RUN date -u +'%Y%m%d.%H%M%S' > /opt/cppm/BUILD
# Merge the acme-ca-certs project directory (contains trust-exclusions.conf default)
# into the directory already populated by the ACME CA cert download RUN block above.
COPY acme-ca-certs/ /opt/cppm/acme-ca-certs/

RUN chmod +x /opt/cppm/*.sh \
    && chmod 755 /opt/cppm/clearpass_upload.py \
    && chmod 755 /opt/cppm/cppm_acme_manager_servers.py \
    && chmod 755 /opt/cppm/cppm_acme_manager_users.py \
    && ln -s /opt/cppm/cppm_acme_manager_servers.py /usr/local/bin/cppm-servers \
    && ln -s /opt/cppm/cppm_acme_manager_users.py   /usr/local/bin/cppm-users

# ── Timezone ──────────────────────────────────────────────────────────────────
ENV TZ=UTC

# ── Single persistent volume – certificates only ─────────────────────────────
# Layout created by entrypoint.sh at first start:
#   /data/certs/<domain>.{cer,key,fullchain.cer,ca.cer}
#   /data/certs/.acme-state/   – acme.sh account keys + cert state
#   /data/certs/.logs/         – operational logs
VOLUME ["/data/certs"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=5 \
    CMD test -f /data/certs/cppm.sinemalab.com.cer || exit 1

ENTRYPOINT ["/opt/cppm/entrypoint.sh"]
