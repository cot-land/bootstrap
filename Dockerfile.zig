FROM debian:bookworm-slim

# Install Zig 0.15.2 for x86_64 Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz | tar xJ -C /opt \
    && ln -s /opt/zig-x86_64-linux-0.15.2/zig /usr/local/bin/zig

WORKDIR /cot
