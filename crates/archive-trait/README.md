# archive-trait

archive-trait provides asynchronous, format-agnostic traits and interfaces
for building and extracting archives.

`Builder::add_file_with_options` accepts the format writer's `ArchiveBuilder::FileOptions`
alongside the format-neutral `EntryMetadata`. `add_file` and recursive builds
use default file options. Writers without per-file settings use `()`.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
