# tarpit

A development CLI for inspecting tar streams and debugging [tar-codec](../tar-codec).

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

## Usage

Use `frames` to inspect individual tar blocks, or `logical` to see members
with their paths, headers, PAX or GNU extensions, and payload blocks.

```shell
cargo run -p tarpit -- frames archive.tar
cargo run -p tarpit -- logical archive.tar.gz
```

To extract an archive into a directory:

```shell
cargo run -p tarpit -- extract archive.tar destination
```

All three commands decompress files whose names end in `.tar.gz`.
