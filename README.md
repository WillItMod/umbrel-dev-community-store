# WillItMod Dev Umbrel Community Store

Development/test Umbrel app store for WillItMod apps.

## Apps

- **Bitcoin Cash** (`willitmod-dev-bch`): BCH full node (BCHN) + solo Stratum v1 pool (ckpool) in a single app.

## Quick setup (BCH solo mining)

1. Install **Bitcoin Cash** and let it sync.
2. Point miners at `stratum+tcp://<umbrel-ip>:3333`.

## Address format note

Many wallets (e.g. Trust Wallet) show Bitcoin Cash addresses in CashAddr format (`q...` / `p...`).

For maximum compatibility with ckpool/miners, use a legacy BCH Base58 address (`1...` / `3...`) as the payout address. If your wallet only shows CashAddr, convert it to legacy (or enable legacy display) before saving.

## Security / provenance

- BCHN runs from Docker Hub image `mainnet/bitcoin-cash-node` (pinned by version tag in `docker-compose.yml`).
- ckpool runs from `ghcr.io/getumbrel/docker-ckpool-solo` (pinned by version tag in `docker-compose.yml`).
- This store repo does not rebuild or modify those upstream images; it only orchestrates them.
