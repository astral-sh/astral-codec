# zip-codec

`zip-codec` reads and writes ZIP archives using seekable Tokio I/O. It supports
Stored and DEFLATE members and writes ZIP64 archives.

## Reading

`ZipArchive::open` reads the central directory. Use `entries()` to list its
members, `member(index)` to open one, or `extract_in` to extract the archive.

```rust,no_run
use zip_codec::{Archive, ZipArchive, extract::ExtractPolicy};

async fn extract() -> Result<(), Box<dyn std::error::Error>> {
    let input = tokio::fs::File::open("input.zip").await?;
    ZipArchive::open(input).await?
        .extract_in("destination", ExtractPolicy::default())
        .await?;
    Ok(())
}
```

Keep the source unchanged while the archive is open. Selecting a member checks
its local records. `validate_all()` checks every member's metadata. Reading a
payload to the end verifies its size and CRC-32. For DEFLATE, the compressed
stream must also end at the declared boundary. Advancing to another member
drains and checks the previous payload.

Use `ZipArchive::builder` to set read limits and ZIP policies before opening.
`ExtractPolicy` controls how members are written to disk.

For an HTTP range source with its own `prefetch` method, the member's declared
range can be fetched before opening it.

```rust,ignore
let range = archive.entries()[index].record_range();
archive.reader_mut().await?.prefetch(range).await?;
let member = archive.member(index).await?;
```

## Writing

`ZipEncoder` streams each payload, then seeks back to fill in its local header.
Start with an empty output positioned at byte zero. Call `finish()` to write
the central directory and end records.

```rust,no_run
use zip_codec::{ArchiveBuilder, EntryMetadata, FilePayload, ZipEncoder};

async fn create() -> Result<(), Box<dyn std::error::Error>> {
    let output = tokio::fs::File::create("output.zip").await?;
    let mut builder = ZipEncoder::new(output).builder();
    let readme = FilePayload::from_path("README.md").await?;
    builder.add_file("README.md", readme, EntryMetadata::default()).await?;
    builder.finish().await?;
    Ok(())
}
```

Nonempty regular files use DEFLATE by default. Set the archive default with
`ZipEncoder::with_compression` or override it for one file with
`ZipFileOptions::with_compression`. Empty files are stored uncompressed.

See the [ZIP compatibility notes](APPNOTE.md) and the
[security model](../../SECURITY.md#zip-codec).
