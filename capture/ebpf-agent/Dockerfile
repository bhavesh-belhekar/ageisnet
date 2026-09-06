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
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir redis==5.2.1

WORKDIR /agent

COPY src ./src
COPY loader ./loader
COPY Makefile .

ENTRYPOINT ["sleep", "infinity"]