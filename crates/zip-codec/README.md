# zip-codec

An asynchronous ZIP reader and writer for Rust. Reads classic ZIP and ZIP64
archives and writes ZIP64 archives with Stored or DEFLATE members.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

> [!IMPORTANT]
>
> This crate is in early development and is not ready for production use.

Both reading and writing require seekable I/O. Encrypted and multi-volume
archives are unsupported. See the [security model](../../SECURITY.md#zip-codec)
and PKWARE's [ZIP specification](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT).

## Writing

```rust
use zip_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, ZipEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = ZipEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

Start with an empty writer at byte zero. The encoder seeks back to overwrite
each local header, so files opened in append mode are unsupported.

The builder also supports `add_directory` and `add_directory_all` through
[archive-trait](../archive-trait).

## Extraction

```rust
use zip_codec::{Archive as _, ZipArchive, extract::ExtractPolicy};

ZipArchive::open(reader).await?
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

`ZipArchive::entries` lists members in central directory order. To read one
member, pass its index to `ZipArchive::member`.

Use `ZipArchive::open_with_policy` to set reader limits and enable optional ZIP
features. `ExtractPolicy` controls how members are written to disk.

## Performance

The wheel corpus benchmark compares indexing, decoding, and extraction with
`zip` and `astral_async_zip`. See the [benchmark instructions](../../CONTRIBUTING.md#zip-wheel-corpus).
