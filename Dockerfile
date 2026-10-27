# bab: the service (`bab serve`), the syncs (`bab sync ...` on a schedule) and `bab sweep`.
# The fga CLI rides along: `bab serve` writes the model from the catalogue at boot and the
# SDK only speaks JSON, so the DSL to JSON step shells out to it.
FROM python:3.12-slim
ARG FGA_VERSION=0.7.20
ARG TARGETARCH=amd64
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 bab \
 && curl -sL "https://github.com/openfga/cli/releases/download/v${FGA_VERSION}/fga_${FGA_VERSION}_linux_${TARGETARCH}.tar.gz" \
    | tar xz -C /usr/local/bin fga
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY bab ./bab
COPY catalogues ./catalogues
RUN pip install --no-cache-dir '.[service,postgres,aws]'
USER bab
ENV BAB_PORT=8080 BAB_FGA_CLI=/usr/local/bin/fga
EXPOSE 8080
ENTRYPOINT ["bab"]
CMD ["serve"]
