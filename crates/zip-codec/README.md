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

Opening validates all record boundaries and redundant headers before exposing
members. Payload reads check CRC-32, exact decoded size, and exact DEFLATE stream
consumption. Advancing or selecting another member drains and validates an
unfinished payload. Errors or cancellation poison the reader.

`Limits` bounds archive size, entry count, metadata, per-member output, and total
output. Payload chunks are capped at 64 KiB. Symbolic-link targets are limited to
65,535 bytes. The source must remain unchanged while reading the archive.

Encryption, signatures, patched data, multi-volume archives, ZIP64 version-2
directories, non-UTF-8 names, ambiguous records, and unaccounted bytes are rejected.
