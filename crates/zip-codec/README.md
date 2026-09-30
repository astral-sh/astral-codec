# zip-codec

Strict, asynchronous ZIP decoding for seekable inputs and streaming ZIP64
encoding, with format-neutral construction and extraction through `archive-trait`.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zip_codec::{Archive, ZipArchive, extract::ExtractPolicy};

let source = tokio::fs::File::open("input.zip").await?;
ZipArchive::open(source).await?
    .extract_in("destination", ExtractPolicy::default()).await?;
# Ok(())
# }
```

Build an archive with seekable output, without buffering whole files:

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zip_codec::{ArchiveBuilder, CompressionMethod, EntryMetadata, ZipEncoder, ZipFileOptions};

let output = tokio::fs::File::create("output.zip").await?;
let mut builder = ZipEncoder::new(output)
    .compression(CompressionMethod::Deflate)
    .builder();
builder.add_file("hello.txt", &b"hello\n"[..], EntryMetadata::default()).await?;
builder.add_file_with_options(
    "raw.bin",
    &b"store these bytes"[..],
    EntryMetadata::default(),
    ZipFileOptions::default().compression(CompressionMethod::Stored),
).await?;
builder.finish().await?;
# Ok(())
# }
```

The output must implement `AsyncWrite + AsyncSeek + Unpin`, be empty, and start
at byte zero. Use `std::io::Cursor<Vec<u8>>` for an in-memory archive.

`ZipFileOptions` overrides compression for one file. Default options, plain
`add_file`, and recursive builds use the encoder's configured compression method.
Empty files are always stored.

`ZipArchive::entries` exposes indexed members; call `directory()` on an entry
to access its central-directory metadata. `ZipArchive::member(index)` selects
an entry. Sequential iteration resumes after the selected entry.
`open_with_limits` and `ZipEncoder::limits` configure resource budgets.

Opening validates the directory. Selecting a member reconciles its local
header, extras, and descriptor before exposing it. `validate_all().await` checks
metadata for every member, including unselected members. Payload reads check
CRC-32, exact decoded size, and exact DEFLATE stream consumption. Advancing or
selecting another member drains and validates an unfinished payload. Errors or
cancellation poison the reader.

`Limits` bounds archive size, entry count, metadata, per-member output, and total
output. Payload chunks are capped at 64 KiB. Symbolic-link targets are limited to
65,535 bytes. The source must remain unchanged while reading the archive.

Encryption, signatures, patched data, multi-volume archives, ZIP64 version-2
directories, non-UTF-8 names or comments, ambiguous records, and unaccounted bytes
are rejected when the affected records are checked. Listing alone does not
validate unselected local records. Archive and member comments must be UTF-8
regardless of the member's UTF-8 flag.

The member adapter supports regular files, directories, symbolic links, APPNOTE
Unix hard links, and the special kinds represented by `archive-trait`. Volume
labels, sockets, and conflicting file-type attributes cannot be projected.
Unknown extra fields are checked as bounded records and otherwise ignored.

Encoding uses ZIP64 even for small archives. Each payload is streamed once, then
the encoder seeks back to fill in the local header's CRC and sizes. No data
descriptors are emitted. Empty members and symbolic-link targets are stored
without compression. Timestamps are fixed at 1980-01-01; Unix permissions retain
only executable intent. DEFLATE and CRC use `flate2` with its pure-Rust `zlib-rs`
backend. `CompressionMethod` is non-exhaustive so further methods can be added
without redesigning the APIs.

See [SECURITY.md](../../SECURITY.md) for resource bounds and validation guarantees.

For HTTP range sources, metadata reads use bounded read-ahead. Local records
are fetched only when selected. To prefetch a whole selected member, obtain its
`record_range()` from `entries()` and call the source's prefetch method through
`reader_mut().await?` before selecting it. The ZIP crates have no HTTP dependency.
Lending the reader drains an active payload first; the caller may move the cursor
but must preserve the source and its contents. Prefetch sizes and the underlying
source's cache policy remain under caller control.

For a source with an async `prefetch` method, the access pattern is:

```rust,ignore
let range = archive.entries()[index].record_range();
archive.reader_mut().await?.prefetch(range).await;
let member = archive.member(index).await?;
```

The declared range includes the local header, compressed payload, and any
trailing descriptor. Prefetching does not mark those records as validated.
