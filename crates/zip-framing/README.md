# zip-framing

`zip-framing` reads ZIP records from a seekable source and serializes ZIP64
headers. Use [`zip-codec`](../zip-codec) for payload decoding, integrity
checks, and filesystem extraction.

## Reading

Pass the same, unchanged source to each operation on an `Index`.

- `Index::read` checks the central directory. Each `IndexedEntry` exposes the
  directory metadata and the declared byte range for prefetching.
- `Index::entry` checks one member's local header, extra fields, and any data
  descriptor against the directory. The resulting `Entry` exposes the member
  kind and payload offset. `Index::resolved` returns a cached entry without I/O.
- `Index::validate_all` checks every member's local records and verifies that
  their byte ranges cover the archive's member data without gaps or overlaps.

`Limits` bounds archive size, entry count, metadata, and declared output sizes.
`Index::read_with_options` configures accepted ZIP features through
`ReadOptions`. By default, the only accepted member extra field is ZIP64.
See the [supported extra fields](../zip-codec/APPNOTE.md#member-extra-fields).

## Writing

`write::PendingMember` gives the local header size before the payload is
written. Pass the CRC-32, sizes, and local header offset to `finish`, then
serialize the local and central headers from the resulting `CompletedMember`.
`write::end_records` serializes the ZIP64 and classic end records.
