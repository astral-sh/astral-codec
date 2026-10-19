# astral-codec

astral-codec is a collection of Rust crates for fast, asynchronous encoding and
decoding of archive formats.

It currently provides tar and ZIP archive support and format-neutral interfaces
for building and extracting archives.

> [!IMPORTANT]
>
> This repository is in a **very early** state of development and is **not**
> considered ready for production use. You will encounter bugs, sharp edges,
> etc.

## Crates

| Crate | Description |
| --- | --- |
| [archive-trait](./crates/archive-trait) | Format-neutral, asynchronous archive construction and extraction. |
| [tar-codec](./crates/tar-codec) | High-level tar encoding and decoding, with pax encoding and POSIX pax/ustar or GNU decoding. |
| [tar-framing](./crates/tar-framing) | Low-level tar framing and member assembly. |
| [zip-codec](./crates/zip-codec) | Seekable ZIP decoding and streaming ZIP64 encoding, with stored and DEFLATE members. |
| [zip-framing](./crates/zip-framing) | Bounded ZIP indexing, record consistency checks, and serialization. |
| [tarpit](./crates/tarpit) | A development-only CLI for inspecting and extracting tar streams. |

See each crate's README for usage and scope.

## Contributing

See [CONTRIBUTING](./CONTRIBUTING.md) for architecture, development commands, and
benchmarking instructions, and [SECURITY](./SECURITY.md) for the security policy
and model.
