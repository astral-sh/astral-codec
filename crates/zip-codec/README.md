# zip-codec

zip-codec is a constrained, asynchronous ZIP encoder and decoder for Rust.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

> [!IMPORTANT]
>
> This crate is in **very early development**. Expect bugs and sharp edges.

**Goals**

- Read classic ZIP and ZIP64 archives with indexed access to individual members
- Write ZIP64 archives with Stored or DEFLATE members, streaming each payload

**Anti-goals**

- Reading or writing archives on non-seekable streams
- Supporting encrypted or multi-volume archives

See the [ZIP compatibility notes](APPNOTE.md) and the [security model](../../SECURITY.md#zip-codec).

## Usage

To write an archive, start with an empty, seekable writer positioned at byte zero.

```rust
use zip_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, ZipEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = ZipEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

Use `add_directory` to add a directory entry or `add_directory_all` to add a
directory and its contents recursively. Nonempty regular files use DEFLATE by default.
Use `ZipEncoder::with_compression` to set the default or
`ZipFileOptions::with_compression` to override it for one file.

To extract an archive, pass a seekable reader. Its contents must stay unchanged
while the archive is open.

```rust
use zip_codec::{Archive as _, ZipArchive, extract::ExtractPolicy};

ZipArchive::open(reader).await?
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

- To set resource limits or reader policies, configure `ZipReadOptions::default()` and call
  `options.open(reader).await?`. The same options can open multiple archives.
- Use `ExtractPolicy` to control how archive members are written to disk.

For random access, `ZipArchive::entries` lists central-directory entries and
`ZipArchive::member(index)` selects one by index.

## Performance

The wheel corpus benchmark compares indexing, decoding, and extraction with
`zip` and `astral_async_zip`. See the [benchmark instructions](../../CONTRIBUTING.md#zip-wheel-corpus).
