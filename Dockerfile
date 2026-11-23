# bab's image. Every input is pinned: the base image by digest, Python packages by
# the lock (uv export --frozen writes requirements with hashes, pip verifies them),
# the fga CLI by version. A bump is a line in a PR with the reason next to it.
# Multi-arch: TARGETARCH is set by buildx (amd64 | arm64); a plain docker build gets amd64.
FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159 AS deps
ARG UV_VERSION=0.11.21
WORKDIR /lock
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir "uv==${UV_VERSION}" \
 && uv export --frozen --no-dev --no-emit-project --extra service --extra postgres --extra aws -o requirements.txt

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ARG FGA_VERSION=0.7.20
ARG TARGETARCH=amd64
# The release passes the day as APT_REFRESH, so the upgrade below runs again on every
# release instead of coming out of the build cache with last month's packages.
ARG APT_REFRESH=
RUN echo "apt refresh: ${APT_REFRESH}" && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 bab \
 && curl -sL "https://github.com/openfga/cli/releases/download/v${FGA_VERSION}/fga_${FGA_VERSION}_linux_${TARGETARCH}.tar.gz" \
    | tar xz -C /usr/local/bin fga
WORKDIR /app
COPY --from=deps /lock/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY bab ./bab
COPY catalogues ./catalogues
RUN pip install --no-cache-dir --no-deps .
USER bab
ENV BAB_PORT=8080 BAB_FGA_CLI=/usr/local/bin/fga
EXPOSE 8080
ENTRYPOINT ["bab"]
CMD ["serve"]
