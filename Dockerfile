
# Dockerfile (robust final)
FROM debian:bookworm-slim

ARG CHAINSAW_VERSION=v2.13.1
ARG CHAINSAW_ASSET=chainsaw_x86_64-unknown-linux-gnu.tar.gz
# ARM64 環境なら:
# ARG CHAINSAW_ASSET=chainsaw_aarch64-unknown-linux-gnu.tar.gz

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl ca-certificates python3 file && \
    rm -rf /var/lib/apt/lists/*

# Fetch & install Chainsaw
RUN set -eux; \
    mkdir -p /opt/chainsaw; \
    curl -sSL -o /tmp/chainsaw.tar.gz \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/${CHAINSAW_VERSION}/${CHAINSAW_ASSET}"; \
    tar -xzf /tmp/chainsaw.tar.gz -C /opt/chainsaw; \
    # 実行ファイルを自動検出
    CS_BIN="$(find /opt/chainsaw -type f -name chainsaw | head -n1)"; \
    test -n "$CS_BIN"; \
    chmod +x "$CS_BIN"; \
    ln -sf "$CS_BIN" /usr/local/bin/chainsaw; \
    # 最終確認（存在 & 実行可能であること）
    test -x /usr/local/bin/chainsaw; \
    /usr/local/bin/chainsaw --version || true; \
    file /usr/local/bin/chainsaw || true

WORKDIR /workspace
COPY scripts/scan_and_report.py /usr/local/bin/scan_and_report.py
ENTRYPOINT ["python3", "/usr/local/bin/scan_and_report.py"]
