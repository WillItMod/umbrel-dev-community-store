# WillItMod Dev Umbrel Community Store

Development/test Umbrel app store for WillItMod apps.

## Apps

- **Bitcoin Cash** (`willitmod-dev-bch`): BCH full node (BCHN) + solo Stratum v1 pool (ckpool) in a single app.

## Quick setup (BCH solo mining)

1. Install **Bitcoin Cash** and let it sync.
2. Point miners at `stratum+tcp://<umbrel-ip>:3333`.

## Address format note

ckpool is Bitcoin-focused; for BCH payouts, legacy Base58 addresses (`1...` / `3...`) are usually the most compatible username format.

## Security / provenance

- BCHN runs from Docker Hub image `mainnet/bitcoin-cash-node` (pinned by digest in `docker-compose.yml`).
- ckpool runs from `ghcr.io/getumbrel/docker-ckpool-solo` (pinned by digest in `docker-compose.yml`).
- This store repo does not rebuild or modify those upstream images; it only orchestrates them and pins exact digests.
