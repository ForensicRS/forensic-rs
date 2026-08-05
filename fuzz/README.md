# Fuzzing the provenance store

This is a standard [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
setup: a nested crate with its own `Cargo.toml`, invisible to the root
package's own `cargo build`/`cargo test` (the root `Cargo.toml` has no
`[workspace]`, so this directory is just an ordinary subdirectory as far as
the root package is concerned).

## Requirements (not part of the main crate's toolchain)

```sh
rustup install nightly
cargo install cargo-fuzz
```

## Running

From this directory:

```sh
cargo +nightly fuzz run store_deserialize
```

Or with a time limit for CI-style smoke runs:

```sh
cargo +nightly fuzz run store_deserialize -- -max_total_time=60
```

## What it exercises

`store_deserialize` feeds arbitrary bytes to
`serde_json::from_slice::<ProvenanceSideTable>`, and on success walks every
resulting `ProvenanceId` through `ProvenanceStore::confidence` and
re-exports via `ProvenanceStore::to_side_table`. A malformed or adversarial
table can encode out-of-bounds source indices or a cyclic `derived_from`
chain — the property under test is that none of this ever panics, hangs, or
allocates unboundedly; `confidence()` must degrade to `Confidence::Unknown`
instead.
