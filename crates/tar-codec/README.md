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

Reading member metadata:

`Member::metadata()` exposes the effective `mtime` in unsigned, integral Unix
seconds. PAX overrides and deletions are resolved before returning the member;
fractional seconds are discarded by the current decoder.

Vendor PAX snapshots are disabled by default, even when the decode policy permits
vendor extensions. Applications that need them must opt in separately:

```rust
use tar_codec::{
    Archive as _, DecodePolicy, Member, MemberPayload as _, PaxDecodePolicy,
    PaxVendorExtensionPolicy, PaxVendorValue, TarArchive,
};

let policy = DecodePolicy::default().pax_policy(
    PaxDecodePolicy::default()
        .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
);
let mut members = TarArchive::new(reader)
    .with_policy(policy)
    .retain_pax_vendor_records(true)
    .members();

while let Some(member) = members.next().await? {
    match member.metadata().pax_vendor_records.get("Acme.attribute") {
        Some(PaxVendorValue::Value(_bytes)) => { /* interpret the bytes */ }
        Some(PaxVendorValue::Deleted) => { /* explicitly deleted */ }
        None => { /* absent from the snapshot */ }
    }
    if let Member::File { payload, .. } | Member::HardLink { payload, .. } = member {
        payload.skip().await?;
    }
}
```

Snapshots offer read-only `get` and `iter` access and can outlive the current
member. Capturing them preserves the existing policy checks, but adds work and
allocations for every member, including inherited global metadata. Ordinary
extraction can leave retention disabled. The application remains responsible for
interpreting vendor values; retained records are not filesystem attributes applied
by `extract_in`.

## Performance

tar-codec aims to be as fast as (or substantially faster than) other
tar libraries for Rust, including [tar] and [astral-tokio-tar].

[tar]: https://crates.io/crates/tar
[astral-tokio-tar]: https://crates.io/crates/astral-tokio-tar

See [BENCHMARKS] for current benchmarks.

[BENCHMARKS]: ./BENCHMARKS.md

The metadata benchmarks isolate in-memory decoding from filesystem I/O and
fixture construction. They compare ordinary decoding, allowing vendor records
without retaining them, and explicitly retaining and reading effective metadata.
Fixtures use 1,024 members with 64-byte payloads and local or inherited global
vendor records.

```shell
# Wall-clock timing without allocation instrumentation.
cargo bench -p tar-codec --bench metadata --locked

# The same workloads with allocation statistics; do not use these times for
# uninstrumented performance comparisons.
cargo bench -p tar-codec --bench metadata_allocations --locked
```
