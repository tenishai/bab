# Sync job image: `bab sync okta|topology` on a schedule (CronJob), or `bab check` for ops.
FROM python:3.12-slim
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 bab
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY bab ./bab
COPY catalogues ./catalogues
RUN pip install --no-cache-dir .
USER bab
ENTRYPOINT ["bab"]
CMD ["--help"]
