# Sandbox image for the PyVul evaluation harness.
#
# Every piece of untrusted code — the vulnerable cases and the agent's own
# proof-of-concept scripts — runs only inside a container built from this image.
# The image is built once, on the host, with network access, at setup time. That
# build step is safe because no untrusted code runs during it; only trusted,
# pinned packages are installed. At run time the container has no network, so it
# can never `pip install` — everything it needs must already be baked in here.
#
# Build (from the repository root):
#   docker build -t pyvul-eval-sandbox:1.0.0 sandbox/
#
# Smoke test (must exit 0):
#   docker run --rm pyvul-eval-sandbox:1.0.0 python -c "import pytest, yaml"

# Base image pinned by digest for reproducibility. The digest, not
# just the `3.12-slim` tag, is what makes a rebuild bit-for-bit repeatable: tags
# are mutable and can be repointed upstream by the maintainers, whereas a digest
# names one exact image.
#
# Provenance — how this digest was obtained (so it is verifiable, not magic):
#   $ docker pull python:3.12-slim
#     Digest: sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf
#   Pinned on 2026-07-03 for linux/amd64. Anyone can reproduce this value with the
#   command above, or without pulling via:
#   $ docker buildx imagetools inspect python:3.12-slim   # prints the same Digest.
#
# To intentionally upgrade the base later: re-run the command, replace the digest
# below with the newly reported one, and bump the sandbox image tag (LABEL below).
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

# The slim base ships neither dependency, and the sandbox cannot install them at
# run time (no network — that is the security boundary), so they are pinned and
# baked in here:
#   - pytest: the `run_pytest` tool executes each case's proof-of-concept tests.
#   - PyYAML: CASE-04 (unsafe deserialization) exercises `yaml.load`.
# Versions are pinned so the sandbox is part of what a result is reproducible
# against; adding a case that needs a new dependency means bumping these pins and
# the image tag together.
RUN pip install --no-cache-dir pytest==8.3.4 PyYAML==6.0.2

# Record the sandbox image version in the image metadata so it can be recovered
# from a built image (e.g. by the startup preflight) even if the local tag
# has drifted. Keep this in step with the `-t pyvul-eval-sandbox:<version>` tag
# used at build time and recorded in every RunResult.
LABEL org.opencontainers.image.title="pyvul-eval-sandbox" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Offline, no-network sandbox for running untrusted PyVul eval cases."
