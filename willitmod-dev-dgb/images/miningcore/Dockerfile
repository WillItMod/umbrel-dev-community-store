FROM mcr.microsoft.com/dotnet/sdk:6.0-jammy as builder

WORKDIR /src

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
      curl && \
    rm -rf /var/lib/apt/lists/*

# Miningcore source is provided as the Docker build context by the GitHub Actions workflow.
COPY . .

# Build a minimal libmultihash for Scrypt (portable across amd64/arm64).
RUN mkdir -p /tmp/axedgb-multihash && \
    cat > /tmp/axedgb-multihash/exports_min.cpp <<'EOF'\n#include <stdint.h>\nextern \"C\" {\n  void scrypt_N_R_1_256(const char* input, char* output, uint32_t N, uint32_t R, uint32_t input_len);\n}\nextern \"C\" void scrypt_export(const char* input, char* output, uint32_t N, uint32_t R, uint32_t input_len)\n{\n  scrypt_N_R_1_256(input, output, N, R, input_len);\n}\nEOF

RUN gcc -c -fPIC -O2 \
      -I/src/src/Native/libmultihash \
      -o /tmp/axedgb-multihash/scryptn.o \
      /src/src/Native/libmultihash/scryptn.c && \
    g++ -shared -fPIC -O2 -std=c++11 \
      -o /tmp/axedgb-multihash/libmultihash.so \
      /tmp/axedgb-multihash/exports_min.cpp \
      /tmp/axedgb-multihash/scryptn.o

# Publish Miningcore binaries.
WORKDIR /src/src/Miningcore
RUN dotnet publish -c Release --framework net6.0 -o /out

# Copy native library next to the published binary.
RUN cp /tmp/axedgb-multihash/libmultihash.so /out/libmultihash.so

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
