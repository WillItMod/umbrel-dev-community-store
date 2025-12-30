# WillItMod Dev Umbrel Community Store

Development/test Umbrel app store for WillItMod apps.

## Apps

- **Bitcoin Cash** (`willitmod-dev-bch`): BCH full node (BCHN) + solo Stratum v1 pool (ckpool) in a single app.
- **DigiByte** (`willitmod-dev-dgb`): DigiByte Core full node + solo Stratum v1 pool (ckpool) in a single app (experimental).

## Quick setup (solo mining)

1. Install the app and let the node sync.
2. Point miners at:
   - BCH: `stratum+tcp://<umbrel-ip>:4567`
   - DGB: `stratum+tcp://<umbrel-ip>:5678`

## Address format notes

**BCH**
Many wallets (e.g. Trust Wallet) show Bitcoin Cash addresses in CashAddr format (`q...` / `p...`).

For maximum compatibility with ckpool/miners, use a legacy BCH Base58 address (`1...` / `3...`) as the payout address. If your wallet only shows CashAddr, convert it to legacy (or enable legacy display) before saving.

**DGB**
Use a DigiByte address (typically Base58 `D...` / `S...` or Bech32 `dgb1...`).

## Security / provenance

- BCHN runs from Docker Hub image `mainnet/bitcoin-cash-node` (pinned by version tag in `docker-compose.yml`).
- ckpool runs from `ghcr.io/getumbrel/docker-ckpool-solo` (pinned by version tag in `docker-compose.yml`).
- This store repo does not rebuild or modify those upstream images; it only orchestrates them.
