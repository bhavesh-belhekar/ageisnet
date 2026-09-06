FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bpftool \
        clang \
        libbpf-dev \
        llvm \
        make \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir redis==5.2.1

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /agent

COPY src ./src
COPY loader ./loader
COPY Makefile .

ENTRYPOINT ["sleep", "infinity"]