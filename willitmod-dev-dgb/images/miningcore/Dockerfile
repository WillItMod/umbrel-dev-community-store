FROM mcr.microsoft.com/dotnet/sdk:6.0-jammy AS builder

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

RUN apt-get update && apt-get -y install --no-install-recommends \
  libzmq5 \
  ca-certificates \
  curl \
  && (apt-get -y install --no-install-recommends libsodium23 || apt-get -y install --no-install-recommends libsodium-dev) \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ ./

# Miningcore P/Invoke uses DllImport("libmultihash") which resolves to liblibmultihash.so on Linux.
RUN ln -sf /app/libmultihash.so /app/liblibmultihash.so

ENV LD_LIBRARY_PATH=/app

EXPOSE 4000-4090
CMD ["./Miningcore", "-c", "config.json"]
