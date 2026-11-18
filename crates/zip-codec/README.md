# zip-codec

zip-codec is a constrained, asynchronous ZIP encoder and decoder for Rust.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

> [!IMPORTANT]
>
> This crate is in **very early development**. Expect bugs and sharp edges.

**Goals**

- Read classic ZIP and ZIP64 archives with indexed access to individual members
- Write ZIP64 archives with Stored or DEFLATE members, streaming each payload
- Support for a subset the ZIP format defined in PKWARE's
  [APPNOTE-6.3.9.TXT](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT)

**Anti-goals**

- Reading or writing archives on non-seekable streams
- Supporting encrypted or multi-volume archives

See the [security model](../../SECURITY.md#zip-codec) as well.

## Usage

### Writing

```rust
use zip_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, ZipEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = ZipEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

zip-codec implements [archive-trait](../archive-trait/README.md), so you can use
`add_directory` and other APIs as well.

### Extraction

```rust
use zip_codec::{Archive as _, ZipArchive, extract::ExtractPolicy};

ZipArchive::open(reader).await?
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

- To configure resource limits and accepted ZIP features, pass a `DecodePolicy` to
  `ZipArchive::open_with_policy(reader, policy).await?`.
- Use `ExtractPolicy` to control how archive members are written to disk.

For random access, `ZipArchive::entries` lists central-directory entries and
`ZipArchive::member(index)` selects one by index.

## Performance

The wheel corpus benchmark compares indexing, decoding, and extraction with
`zip` and `astral_async_zip`. See the [benchmark instructions](../../CONTRIBUTING.md#zip-wheel-corpus).
