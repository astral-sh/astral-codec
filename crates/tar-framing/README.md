# tar-framing

Low-level record framing for POSIX pax/ustar and GNU tar streams.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
Most users should use [tar-codec](../tar-codec) to read or write archives.

## Reading

`logical::TarReader` groups each member with its PAX or GNU extensions. To
list member paths, including paths set by those extensions:

```rust
use tar_framing::logical::TarReader;

let mut archive = TarReader::new(reader);
while let Some(member) = archive.next_frame().await? {
    println!("{}", String::from_utf8_lossy(member.effective_path()?));
}
```

To inspect individual 512-byte blocks, use `stream::TarStream`. It exposes
extension headers even when there is no following member. The final data frame
of a PAX extension includes its parsed records.

Both readers reject streams that mix pax and GNU headers. Use `with_policy` to
set extension size limits or allow additional numeric header formats.

## Writing

The `write` module constructs pax member blocks in memory. The caller writes
them to the archive.

## Benchmarking

```shell
cargo bench -p tar-framing --bench framing --locked
```

See [CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for CodSpeed and smoke-test commands.
