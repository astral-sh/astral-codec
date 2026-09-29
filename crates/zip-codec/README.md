# zip-codec

Strict, asynchronous ZIP decoding for seekable inputs, with format-neutral
iteration and extraction through `archive-trait`.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use zip_codec::{Archive, ZipArchive, extract::ExtractPolicy};

let source = tokio::fs::File::open("input.zip").await?;
ZipArchive::open(source).await?
    .extract_in("destination", ExtractPolicy::default()).await?;
# Ok(())
# }
```

Opening validates the directory. Selecting a member reconciles its local
header, extras, and descriptor before exposing it. `validate_all().await` checks
metadata for every member, including unselected members. Payload reads check
CRC-32, exact decoded size, and exact DEFLATE stream consumption. Advancing or selecting another member drains and validates an
unfinished payload. Errors or cancellation poison the reader.

`Limits` bounds archive size, entry count, metadata, per-member output, and total
output. Payload chunks are capped at 64 KiB. Symbolic-link targets are limited to
65,535 bytes. The source must remain unchanged while reading the archive.

Encryption, signatures, patched data, multi-volume archives, ZIP64 version-2
directories, non-UTF-8 names, ambiguous records, and unaccounted bytes are rejected.

For HTTP range sources, metadata reads use bounded read-ahead. Local records
are fetched only when selected. To prefetch a whole selected member, obtain its
`record_range()` from `entries()` and call the source's prefetch method through
`reader_mut().await?` before selecting it. The ZIP crates have no HTTP dependency.
Lending the reader drains an active payload first; the caller may move the cursor
but must preserve the source and its contents. Prefetch sizes and the underlying
source's cache policy remain under caller control.
