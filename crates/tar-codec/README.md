# tar-codec

An asynchronous tar reader and writer for Rust. Reads POSIX pax/ustar and GNU
archives and writes pax archives. The reader rejects UNIX v7 archives and
streams that mix GNU and pax headers.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

> [!IMPORTANT]
>
> This crate is in early development and is not ready for production use.

## Writing

```rust
use tar_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, TarEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = TarEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

Use `add_directory` for a directory entry or `add_directory_all` to include its
contents. Set `Builder::with_policy` before adding members to configure name
validation and handling of symlinks.

For compressed output such as `.tar.gz`, wrap the writer in a compressor from
[async-compression](https://docs.rs/async-compression/latest/async_compression/).

## Extraction

```rust
use tar_codec::{Archive as _, TarArchive, extract::ExtractPolicy};

TarArchive::new(reader)
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

Use `TarArchive::with_policy` to configure GNU and pax decoding. `ExtractPolicy`
controls how members are written to disk.

## Performance

See [BENCHMARKS](./BENCHMARKS.md) for comparisons with `tar` and
`astral-tokio-tar`.
