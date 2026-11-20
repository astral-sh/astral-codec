# archive-trait

Asynchronous traits for reading and writing archives.

This crate is a component of [astral-codec](https://github.com/astral-sh/astral-codec).
Both [tar-codec](../tar-codec) and [zip-codec](../zip-codec) implement these traits.

## Reading

A function that takes an `Archive` can read either format. For example, to
print each member's path:

```rust
use archive_trait::Archive;

async fn list_paths<A: Archive>(archive: A) -> Result<(), A::Error> {
    let mut members = archive.members();
    while let Some(member) = members.next().await? {
        println!("{}", member.metadata().path);
    }
    Ok(())
}
```

To extract the members to a directory, use `Archive::extract_in` with an
`ExtractPolicy`.

## Writing

Call `ArchiveBuilder::builder` on a tar or ZIP encoder to get a `Builder`.
Pass `EntryMetadata` to `Builder::add_file` to use the encoder's defaults,
or pass the encoder's file options to override them for one file.
`Builder::add_directory_all` adds a directory and its contents recursively.
