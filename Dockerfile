FROM alpine:3.19

LABEL maintainer="Network Engineering"
LABEL description="Self-contained acme.sh certificate manager for Aruba ClearPass CPPM"
LABEL version="2.1"

# ── System packages ───────────────────────────────────────────────────────────
RUN apk add --no-cache \
    bash \
    curl \
    git \
    openssl \
    python3 \
    py3-pip \
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
RUN mkdir -p /opt/cppm/le-certs \
    && curl -fsSL https://letsencrypt.org/certs/isrgrootx1.pem \
            -o /opt/cppm/le-certs/isrg-root-x1.pem \
    && curl -fsSL https://letsencrypt.org/certs/isrg-root-x2.pem \
            -o /opt/cppm/le-certs/isrg-root-x2.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/r10.pem \
            -o /opt/cppm/le-certs/lets-encrypt-r10.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/r11.pem \
            -o /opt/cppm/le-certs/lets-encrypt-r11.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/e5.pem \
            -o /opt/cppm/le-certs/lets-encrypt-e5.pem \
    && curl -fsSL https://letsencrypt.org/certs/2024/e6.pem \
            -o /opt/cppm/le-certs/lets-encrypt-e6.pem \
    && for pem in /opt/cppm/le-certs/*.pem; do \
           subj=$(openssl x509 -noout -subject -in "$pem") \
           && echo "  OK: $(basename $pem) -> $subj" \
           || { echo "ERROR: invalid PEM: $pem"; exit 1; }; \
       done \
    && echo "All $(ls /opt/cppm/le-certs/*.pem | wc -l) CA certs validated."

# ── Copy application scripts ──────────────────────────────────────────────────
RUN mkdir -p /opt/cppm
COPY scripts/ /opt/cppm/
COPY config/crontab /etc/crontabs/root

RUN chmod +x /opt/cppm/*.sh \
    && chmod 755 /opt/cppm/clearpass_upload.py

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
