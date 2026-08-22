# Batteries included: the point of the image is that GitLab CI, Jenkins and
# CircleCI users get carabiner *and* the scanners it wraps, with nothing to
# install and no Python on the host.
#
# The base is pinned by digest, not by tag. carabiner reports mutable image tags
# as a finding (CI003 / GL003); shipping one here would be indefensible.
FROM python:3.13-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1

# Every downloaded binary is checksum-verified against the publisher's own
# checksum file. An unverified curl-into-a-security-image is the supply-chain
# hole this tool exists to complain about.
ARG GITLEAKS_VERSION=8.28.0
ARG GITLEAKS_SHA=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
ARG OSV_VERSION=2.5.1
ARG OSV_SHA=f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl git; \
    rm -rf /var/lib/apt/lists/*; \
    \
    curl -sSfL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    \
    curl -sSfL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64"; \
    echo "${OSV_SHA}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod +x /usr/local/bin/osv-scanner; \
    \
    rm -f /tmp/gitleaks.tar.gz; \
    gitleaks version; osv-scanner --version

WORKDIR /opt/carabiner
COPY pyproject.toml README.md LICENSE ./
COPY carabiner ./carabiner
RUN pip install --no-cache-dir --disable-pip-version-check .

# Nothing here needs root. A scanner running as root in someone else's pipeline
# is a bigger risk than whatever it finds.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin carabiner
USER 10001

# git refuses to operate on a directory owned by someone else, which is exactly
# what a mounted repo looks like from inside the container.
RUN git config --global --add safe.directory '*'

WORKDIR /repo
ENTRYPOINT ["carabiner"]
CMD ["scan"]
