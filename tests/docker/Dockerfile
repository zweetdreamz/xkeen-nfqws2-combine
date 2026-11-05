# syntax=docker/dockerfile:1
#
# Test image for xkeen-nfqws2-control (tag: kdn-tests:local).
# Local test environment (no GitHub Actions workflow): Ubuntu 24.04,
# dash, busybox, jq, shellcheck, Node 22 and Playwright 1.56.1 with Chromium,
# plus two CPython builds selectable at run time (3.13.9 default, 3.12 compatibility).
#
# Build:  sh tests/docker/run-tests.sh --build
#    or:  docker build -t kdn-tests:local tests/docker

ARG UBUNTU=ubuntu:24.04
ARG NODE_IMAGE=node:22.23.4-bookworm-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.4

FROM ${UV_IMAGE} AS uv
FROM ${NODE_IMAGE} AS node

FROM ${UBUNTU}

ARG PY313=3.13.9
ARG PY312=3.12.15
ARG PYTEST_VERSION=9.1.1
ARG COVERAGE_VERSION=7.17.0
ARG RUFF_VERSION=0.17.3
ARG PLAYWRIGHT_VERSION=1.56.1

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    UV_NO_CACHE=1 \
    NODE_PATH=/opt/playwright/node_modules \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

# Tools the shell suites and the lint job use. coreutils (sha256sum, timeout),
# diffutils (cmp) and util-linux (setpriv) come with the base image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      busybox dash jq curl ca-certificates openssl shellcheck procps \
 && rm -rf /var/lib/apt/lists/*

# CPython from python-build-standalone, one venv per version: /opt/py/<X.Y>.
COPY --from=uv /uv /usr/local/bin/uv
RUN uv python install "$PY313" "$PY312" \
 && for v in "$PY313" "$PY312"; do \
      short="${v%.*}"; \
      uv venv --python "$v" "/opt/py/$short" \
      && uv pip install --compile-bytecode --python "/opt/py/$short/bin/python" \
           "pytest==$PYTEST_VERSION" "coverage==$COVERAGE_VERSION" \
      || exit 1; \
    done \
 && uv pip install --python /opt/py/3.13/bin/python "ruff==$RUFF_VERSION" \
 && ln -s /opt/py/3.13/bin/ruff /usr/local/bin/ruff \
 && rm -rf /opt/uv-python/*/lib/python3.*/test /root/.local \
 && rm -f /usr/local/bin/uv

# Node 22 from the official image (binary + bundled npm).
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Playwright + headless Chromium shell (the panel UI test launches headless)
# and its system libraries.
RUN mkdir -p /opt/playwright \
 && cd /opt/playwright \
 && npm init -y >/dev/null \
 && npm install --no-audit "playwright@$PLAYWRIGHT_VERSION" \
 && apt-get update \
 && ./node_modules/.bin/playwright install --with-deps --only-shell chromium \
 && rm -rf /var/lib/apt/lists/* /root/.npm /tmp/* \
 && chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH"

# git only turns the copied working tree into what a checkout on Linux has:
# .gitignore-d files dropped, line endings per .gitattributes.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# Not in CI: lets test_telegram_mtproto cross-check its pure-Python AES-CTR
# against a reference instead of skipping.
ARG CRYPTOGRAPHY_VERSION=50.0.2
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    for v in 3.13 3.12; do \
      uv pip install --compile-bytecode --python "/opt/py/$v/bin/python" \
        "cryptography==$CRYPTOGRAPHY_VERSION" || exit 1; \
    done

# Parallel test workers and combined branch coverage (development image only).
ARG XDIST_VERSION=3.8.0
ARG PYTEST_COV_VERSION=7.1.0
RUN --mount=from=uv,source=/uv,target=/usr/local/bin/uv \
    for v in 3.13 3.12; do \
      uv pip install --compile-bytecode --python "/opt/py/$v/bin/python" \
        "pytest-xdist==$XDIST_VERSION" "pytest-cov==$PYTEST_COV_VERSION" || exit 1; \
    done

# Unprivileged test user (CI runs as a normal user); the entry script drops
# to it and passes CAP_NET_ADMIN as an ambient capability for SO_MARK.
RUN useradd --create-home --uid 1001 --shell /bin/bash tester \
 && mkdir -p /var/cache/kdn/nfqws2-blobs /work \
 && chown tester:tester /work

COPY kdn-test-entry.sh /usr/local/bin/kdn-test-entry
RUN chmod 0755 /usr/local/bin/kdn-test-entry

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/kdn-test-entry"]
