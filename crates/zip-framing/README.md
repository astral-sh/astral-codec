# zip-framing

Low-level, asynchronous record framing for classic ZIP and ZIP64 archives.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
Most callers should use [zip-codec](../zip-codec) for encoding, payload
decoding, and extraction.

## Reading

`Index::read` reads the central directory from a seekable source. Use the same
source for subsequent reads and keep its contents unchanged while using the index.

- `Index::entries` returns an `IndexedEntry` for each member in directory order.
  It exposes the directory metadata and the declared byte range for prefetching.
- `Index::entry` checks a selected member's local header, extra fields, and any
  data descriptor against the directory. The resulting `Entry` exposes the
  member kind and payload offset. `Index::resolved` retrieves a cached entry
  without I/O.

Use `Index::validate_all` to check every member's local records and verify
that the member ranges cover the space before the central directory without
gaps or overlaps. Payload decoding and CRC-32 verification belong to zip-codec.

`Limits` bounds archive size, entry count, metadata, and declared output sizes.
Pass `ReadOptions` to `Index::read_with_options` to enable features such as
[member extra fields beyond ZIP64](../zip-codec/APPNOTE.md#member-extra-fields).

## Writing

The `write` module serializes ZIP64 records into byte buffers.
`PendingMember::local_header_size` gives the space to reserve for a member's
header. Once the CRC-32, sizes, and local header offset are known, call
`finish` to get a `CompletedMember` that serializes both headers.
`write::end_records` produces the ZIP64 and classic end records.

## Benchmarking

Run the framing benchmarks with Cargo.

```shell
cargo bench -p zip-framing --bench framing --locked
```

The suite measures header serialization, central-directory indexing, and
uncached local-record validation on in-memory ZIP64 archives.
See [CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for CodSpeed and smoke-test commands.
