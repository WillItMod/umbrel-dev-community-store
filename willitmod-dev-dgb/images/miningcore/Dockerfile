FROM mcr.microsoft.com/dotnet/sdk:6.0-jammy as builder

WORKDIR /src

ARG TARGETARCH

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
      build-essential \
      libssl-dev \
      pkg-config \
      libboost-all-dev \
      libsodium-dev \
      libzmq5 \
      libzmq3-dev \
      ca-certificates \
      curl \
      python3 && \
    rm -rf /var/lib/apt/lists/*

# Miningcore source is provided as the Docker build context by the GitHub Actions workflow.
COPY . .

# libmultihash includes optional x86 SIMD implementations; buildx arm64 needs the portable ref variant.
RUN python3 - <<'PY'\nimport os\nfrom pathlib import Path\narch = (os.environ.get('TARGETARCH') or '').strip()\nif arch and arch != 'amd64':\n    exports = Path('src/Native/libmultihash/exports.cpp')\n    text = exports.read_text(encoding='utf-8', errors='replace')\n    old = '#ifdef _WIN32\\n#include \"blake2/ref/blake2.h\"\\n#else\\n#include \"blake2/sse/blake2.h\"\\n#endif'\n    new = '#ifdef _WIN32\\n#include \"blake2/ref/blake2.h\"\\n#elif defined(__x86_64__) || defined(__i386__)\\n#include \"blake2/sse/blake2.h\"\\n#else\\n#include \"blake2/ref/blake2.h\"\\n#endif'\n    if old in text:\n        text = text.replace(old, new)\n        exports.write_text(text, encoding='utf-8')\n\n    mk = Path('src/Native/libmultihash/Makefile')\n    mkt = mk.read_text(encoding='utf-8', errors='replace')\n    mkt = mkt.replace('blake2/sse/blake2s.o blake2/sse/blake2b.o', 'blake2/ref/blake2s-ref.o blake2/ref/blake2b-ref.o')\n    mk.write_text(mkt, encoding='utf-8')\nPY\n+
# Build the native multihash library (required for scrypt and several other algos).
WORKDIR /src/src/Native/libmultihash
RUN make clean && make

# Publish Miningcore binaries.
WORKDIR /src/src/Miningcore
RUN dotnet publish -c Release --framework net6.0 -o /out

# Copy native library next to the published binary.
RUN cp /src/src/Native/libmultihash/libmultihash.so /out/libmultihash.so

FROM mcr.microsoft.com/dotnet/aspnet:6.0-jammy

WORKDIR /app

RUN apt-get update && \
    apt-get -y install --no-install-recommends \
      libzmq5 \
      ca-certificates \
      curl && \
    (apt-get -y install --no-install-recommends libsodium23 || apt-get -y install --no-install-recommends libsodium-dev) && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ ./

# Miningcore P/Invoke uses DllImport("libmultihash") which resolves to liblibmultihash.so on Linux.
RUN ln -sf /app/libmultihash.so /app/liblibmultihash.so

ENV LD_LIBRARY_PATH=/app

EXPOSE 4000-4090
CMD ["./Miningcore", "-c", "config.json"]
