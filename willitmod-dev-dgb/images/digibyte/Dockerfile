FROM debian:bookworm-slim

# v8.26.1 does not publish an arm64 Linux tarball upstream.
# v8.22.2 is the newest DigiByte Core release with official linux/amd64 + linux/arm64 tarballs.
ARG TARGETARCH
ARG DGB_RELEASE_TAG="v8.22.2"
ARG DGB_AMD64_SHA256="edfcc9df8c2ecbba9b9e8d2332dee1ec3d053554c3700ca0151477f7375fc342"
ARG DGB_ARM64_SHA256="9e3fde26454fae9036973c931f8ba3c354c73afe1d0a598f573e227b12c73ad8"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl tar libstdc++6 libgcc-s1 libevent-2.1-7 && \
    rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-}" in \
      amd64) asset="digibyte-8.22.2-x86_64-linux-gnu.tar.gz"; sha="${DGB_AMD64_SHA256}" ;; \
      arm64) asset="digibyte-8.22.2-aarch64-linux-gnu.tar.gz"; sha="${DGB_ARM64_SHA256}" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH:-<unset>}"; exit 1 ;; \
    esac; \
    url="https://github.com/DigiByte-Core/digibyte/releases/download/${DGB_RELEASE_TAG}/${asset}"; \
    curl -fsSL -o /tmp/dgb.tar.gz "${url}"; \
    echo "${sha}  /tmp/dgb.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/digibyte; \
    tar -xzf /tmp/dgb.tar.gz -C /opt/digibyte --strip-components=1; \
    rm -f /tmp/dgb.tar.gz; \
    install -m 0755 /opt/digibyte/bin/digibyted /usr/local/bin/digibyted; \
    install -m 0755 /opt/digibyte/bin/digibyte-cli /usr/local/bin/digibyte-cli; \
    install -m 0755 /opt/digibyte/bin/digibyte-tx /usr/local/bin/digibyte-tx; \
    install -m 0755 /opt/digibyte/bin/digibyte-util /usr/local/bin/digibyte-util; \
    install -m 0755 /opt/digibyte/bin/digibyte-wallet /usr/local/bin/digibyte-wallet

ENV LD_LIBRARY_PATH="/opt/digibyte/lib"

RUN groupadd -g 1000 umbrel 2>/dev/null || true && \
    useradd -m -u 1000 -g 1000 umbrel 2>/dev/null || true && \
    mkdir -p /data && chown -R 1000:1000 /data

USER 1000:1000

EXPOSE 12024 14022

CMD ["digibyted", "-datadir=/data", "-printtoconsole"]
