# zip-framing

Low-level record framing for classic ZIP and ZIP64 archives.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
Most users should use [zip-codec](../zip-codec) to read or write archives.

## Reading

`Index::read` reads the central directory from an asynchronous, seekable source.
You can list member names without reading their local headers:

```rust
use zip_framing::Index;

let index = Index::read(&mut reader).await?;
for member in index.entries() {
    println!("{}", member.directory().path());
}
```

To get a member's payload offset, call `Index::entry` with the same reader and
the member's index. This checks its local records against the central directory.
The archive must stay unchanged between reads.

Use `Index::validate_all` to check every member's records. Payload decoding and
CRC-32 verification are handled by zip-codec. To change the reader's limits or
enable optional ZIP features, pass an `IndexPolicy` to `Index::read_with_policy`.

## Writing

The `write` module constructs ZIP64 local headers, central directory headers,
and end records in memory. The caller writes them to the archive.

## Benchmarking

```shell
cargo bench -p zip-framing --bench framing --locked
```

See [CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for the benchmark descriptions and CodSpeed commands.
