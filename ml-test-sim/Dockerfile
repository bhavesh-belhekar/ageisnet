FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /attacks

COPY scripts/ /attacks/scripts/
COPY entrypoint.sh /attacks/entrypoint.sh
RUN chmod +x /attacks/entrypoint.sh

ENTRYPOINT ["/attacks/entrypoint.sh"]
