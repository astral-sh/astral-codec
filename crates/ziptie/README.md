# ziptie

A development CLI for inspecting ZIP archives and debugging [zip-codec](../zip-codec).

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).

## Usage

All three commands read a seekable file using the default ZIP reader policies.
The file can have any extension, including `.whl`.

`frames` checks each local header and any data descriptor against the central
directory. It lists entries in central directory order with their record ranges,
payload offsets, compression methods, declared sizes, and expected CRC-32 values.
Offsets are measured in bytes from the start of the archive. Range ends are exclusive.

```shell
cargo run -p ziptie -- frames archive.zip
```

`logical` also decodes each member and verifies its payload size and CRC-32.
It shows member kinds, paths, link targets, and executable flags, and reports
the decoded byte count after verifying each file.

```shell
cargo run -p ziptie -- logical package.whl
```

`extract` writes members into a directory using the default extraction policy.

```shell
cargo run -p ziptie -- extract archive.zip destination
```
