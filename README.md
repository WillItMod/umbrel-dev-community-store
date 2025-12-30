# WillItMod Dev Umbrel Community Store

Development/test Umbrel app store for WillItMod apps.

## Apps

- **Bitcoin Cash Node** (`willitmod-dev-bch-node`): BCH full node (BCHN) with pruning enabled by default.
- **Bitcoin Cash Solo Pool** (`willitmod-dev-bch-solo-pool`): Stratum v1 solo pool (ckpool) wired for BCH.

## Quick setup (BCH solo mining)

1. Install **Bitcoin Cash Node** and let it fully sync.
2. Install **Bitcoin Cash Solo Pool**.
3. Open the solo pool app and configure RPC connection settings in the web UI.
4. Point miners at `stratum+tcp://<umbrel-ip>:3333`.

## Address format note

ckpool is Bitcoin-focused; for BCH payouts, legacy Base58 addresses (`1...` / `3...`) are usually the most compatible username format.
