# archive-trait

archive-trait provides asynchronous, format-agnostic traits and interfaces
for building and extracting archives.

`Builder::add_file` accepts format-neutral `EntryMetadata` or the format writer's
`ArchiveBuilder::FileOptions`. Converting `EntryMetadata` preserves the writer's
configured defaults, including during recursive builds. Writers without
format-specific settings can use `EntryMetadata` directly.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
