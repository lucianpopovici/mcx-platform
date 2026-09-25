# One Containerfile for every release image (PLT-GEN-001, VP1-BND-006).
#
# Build it from an image directory made by tools/package.py, never from the
# repository root:
#
#   python3 tools/package.py --profile frmcs --out dist
#   podman build -t mcx-platform-frmcs dist/mcx-platform-frmcs
#
# It takes no profile argument and sets no MCX_* variable. The image carries
# one profile, and still refuses to start until the deployment names it
# (MCX_PROFILE) along with every other required setting (PLT-GEN-004).
FROM docker.io/library/python:3.11-slim

WORKDIR /opt/mcx-platform
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Record which platform this is. MANIFEST.json carries the core hash that is
# identical across every image built from the same commit.
LABEL org.opencontainers.image.title="mcx-platform" \
      org.opencontainers.image.description="MC services platform: shared core plus one profile"

RUN useradd --system --uid 10001 mcx
USER mcx

ENTRYPOINT ["python3", "-m", "service"]
