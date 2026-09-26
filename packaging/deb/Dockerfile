# syntax=docker/dockerfile:1
#
# Builds the self-contained tree for the frp-jump-client .deb: a private,
# portable CPython (python-build-standalone, via uv) plus frp-jump's
# dependencies, all under /opt/frp-jump-client -- never touches the
# device's own Python/pip/apt. See packaging/deb/build.sh, which drives
# this per target arch and turns the result into a .deb.
#
# Build args:
#   BASE_PLATFORM  buildx platform for the target device, e.g. linux/arm64
#   UV_TARGET      uv's release-asset target triple for that platform,
#                  e.g. aarch64-unknown-linux-gnu (see build.sh's mapping)
#   FRP_JUMP_VERSION  exact version to install from PyPI (must already be
#                  published -- this Dockerfile does not build frp-jump
#                  itself, only packages the already-released wheel)
ARG BASE_PLATFORM

# Runs natively (build host arch, no QEMU) -- fetches uv's own release
# binary for the TARGET arch. Copying a file between build stages doesn't
# execute anything, so this sidesteps ever running uv's installer script
# (which needs curl+ca-certificates) under emulation.
FROM curlimages/curl:latest AS fetch-uv
ARG UV_TARGET=x86_64-unknown-linux-gnu
USER root
RUN curl -fSL --retry 5 --retry-all-errors --retry-delay 3 \
    -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/latest/download/uv-${UV_TARGET}.tar.gz" \
    && tar -xzf /tmp/uv.tar.gz -C /usr/local/bin --strip-components=1 "uv-${UV_TARGET}/uv" \
    && rm /tmp/uv.tar.gz

FROM --platform=$BASE_PLATFORM debian:bullseye-slim AS build
COPY --from=fetch-uv /usr/local/bin/uv /usr/local/bin/uv

# armv7 (WB7 and earlier) has no prebuilt `cffi` wheel on PyPI
# (cryptography's C-extension dependency) -- unlike amd64/arm64, it must
# compile from source, which needs a C toolchain. Installed only in this
# throwaway build image, never on the device itself.
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends gcc libffi-dev libc6-dev \
    && rm -rf /var/lib/apt/lists/*

ARG PY_VERSION=3.12
ARG PREFIX=/opt/frp-jump-client
ARG FRP_JUMP_VERSION

# Portable, self-contained CPython build (python-build-standalone) --
# never touches /usr/bin/python3 or apt. Named deterministically by uv as
# cpython-<version>-<libc-arch>, so the glob below is stable across archs.
RUN uv python install --install-dir "${PREFIX}/python" "${PY_VERSION}"
RUN rm -rf "${PREFIX}/python/.temp" "${PREFIX}/python/.lock" "${PREFIX}/python/.gitignore"

RUN PYBIN=$(echo "${PREFIX}"/python/cpython-"${PY_VERSION}".*/bin/python3) \
    && test -x "$PYBIN" \
    && uv pip install --python "$PYBIN" --target "${PREFIX}/site-packages" "frp-jump==${FRP_JUMP_VERSION}"

# Point the bundled interpreter at our site-packages by default, so the
# pip-generated console-script wrappers (whose shebang is already this
# exact interpreter path -- fixed by PREFIX being an absolute, final
# install path) work with no separate PYTHONPATH wrapper needed.
RUN INTERP_SITE_PACKAGES=$(find "${PREFIX}/python" -maxdepth 4 -type d -name site-packages) \
    && test -d "$INTERP_SITE_PACKAGES" \
    && echo "${PREFIX}/site-packages" > "$INTERP_SITE_PACKAGES/frp-jump.pth"

# Trim what a device install never needs: caches, docs, a CLI tool's
# never-used tkinter/dbm (and their Tcl/Tk libs), and the interpreter's
# own bundled pip/idle/2to3 -- we never run pip anywhere, on the device or
# in this image after the install step above. No `strip` pass: it
# corrupted the amd64 interpreter's dynamic symbol versioning on a first
# attempt (see git history) -- not worth the risk for the size saved.
RUN find "${PREFIX}" -name '__pycache__' -type d -exec rm -rf {} + \
    && rm -rf "${PREFIX}"/python/cpython-*/share/man \
              "${PREFIX}"/python/cpython-*/share/terminfo \
              "${PREFIX}"/python/cpython-*/lib/python3.12/test \
              "${PREFIX}"/python/cpython-*/lib/python3.12/idlelib \
              "${PREFIX}"/python/cpython-*/lib/python3.12/tkinter \
              "${PREFIX}"/python/cpython-*/lib/python3.12/lib-dynload/_tkinter*.so \
              "${PREFIX}"/python/cpython-*/lib/python3.12/lib-dynload/_dbm*.so \
              "${PREFIX}"/python/cpython-*/lib/libtcl* \
              "${PREFIX}"/python/cpython-*/lib/libtk* \
              "${PREFIX}"/python/cpython-*/lib/itcl* \
              "${PREFIX}"/python/cpython-*/lib/thread[0-9]* \
              "${PREFIX}"/python/cpython-*/lib/python3.12/site-packages/pip \
              "${PREFIX}"/python/cpython-*/lib/python3.12/site-packages/pip-*.dist-info \
              "${PREFIX}"/python/cpython-*/bin/pip* \
              "${PREFIX}"/python/cpython-*/bin/idle* \
              "${PREFIX}"/python/cpython-*/bin/2to3*

FROM scratch AS export
COPY --from=build /opt/frp-jump-client /out
