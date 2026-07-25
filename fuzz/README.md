# P2WLAN fuzz targets

This directory contains cargo-fuzz targets that harden wire-format parsers.

Install and run:

```bash
cargo install cargo-fuzz
cargo fuzz run pnch_parser
```

The `pnch_parser` target covers legacy PNCH v1 decoding plus authenticated
PNCH v2 identity peeking and MAC-checked decoding with representative keys from
unit tests and protocol golden vectors.
