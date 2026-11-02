# tar-codec

tar-codec is a small, fast, constrained tar encoder and decoder for Rust.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

> [!IMPORTANT]
>
> This crate is in a **very early** state of development and is **not**
> considered ready for production use. You will encounter bugs, sharp edges,
> etc.

Goals:

- Fast, asynchronous, minimally ambiguous, strict pax-style tar encoding
- Fast, asynchronous tar decoding for distinct POSIX pax/ustar or GNU archive streams

Anti-goals:

- Encoding support for anything other than pax
- Decoding support for legacy (pre-ustar, "UNIX v7") archives
- Decoding archives that mix POSIX pax/ustar and GNU framing in one stream

## Usage

Encoding/archive serialization:

```rust
use tar_codec::{ArchiveBuilder as _, EntryMetadata, FilePayload, TarEncoder};

let payload = FilePayload::from_path("README.md").await?;
let mut encoder = TarEncoder::new(&mut writer).builder();
encoder
    .add_file("README.md", payload, EntryMetadata::default())
    .await?;
encoder.finish().await?;
```

Apart from `Builder::add_file`, you can use:

- `Builder::add_directory` to add a single directory (just the directory, not any contents)
- `Builder::add_directory_all` to recursively add an on-filesystem directory

See `Builder::with_policy` for policy knobs that
can be changed during building.

Note that `tar-codec` does **not** perform compression for you.
If you want a compressed tar stream (like a `.tar.gz`) consider
supplying an adapted writer, such as from the [async-compression]
crate.

[async-compression]: https://docs.rs/async-compression/latest/async_compression/

Decoding/extracting:

```rust
use tar_codec::{Archive as _, TarArchive, extract::ExtractPolicy};

TarArchive::new(reader)
    .extract_in("destination", ExtractPolicy::default())
    .await?;
```

Unlike encoding, decoding/extraction has two policy layers:

- Use `TarArchive::with_policy` to control various aspects of GNU or pax handling.
- Use `extract::ExtractPolicy` to control various aspects of how archives become
  real paths on the host filesystem.

Consumers that store filesystem names as bytes can use
`TarArchive::next_byte_member` instead of the UTF-8 `Archive::next_member` API:

```rust
use tar_codec::{ByteMember, MemberPayload as _, TarArchive};

let mut archive = TarArchive::new(reader);
let mut chunk = Vec::new();
while let Some(member) = archive.next_byte_member().await? {
    // Validate member.metadata().path before using it as a filesystem path.
    if let ByteMember::File { metadata, mut payload, .. } = member {
        while payload.next_chunk(&mut chunk, 64 * 1024).await? {
            // Store chunk under the validated byte path in metadata.path.
        }
    }
}
```

`ByteMember` retains effective paths and link targets as `Vec<u8>`, with the
same framing and decode-policy checks. Non-UTF-8 pax `path` and `linkpath`
records require `hdrcharset=BINARY`; USTAR and GNU names retain their raw
bytes. Consumers are responsible for path and link validation. The existing
UTF-8 member and extraction APIs continue to reject non-UTF-8 names.

## Performance

tar-codec aims to be as fast as (or substantially faster than) other
tar libraries for Rust, including [tar] and [astral-tokio-tar].

[tar]: https://crates.io/crates/tar
[astral-tokio-tar]: https://crates.io/crates/astral-tokio-tar

See [BENCHMARKS] for current benchmarks.

[BENCHMARKS]: ./BENCHMARKS.md
