# zip-framing

Asynchronous, bounded indexing of seekable ZIP archives. `Index::read` checks
the central directory; `Index::entry` reconciles a selected local header,
ZIP64 extensions, and data descriptor before returning a checked `Entry`.
Successful resolutions are cached. `Index::validate_all` checks complete
physical coverage and redundant metadata, including unselected members.
Payload integrity and compression belong to `zip-codec`.

Directory reads use a bounded 64 KiB window; selected local records use a 4 KiB
window bounded by the next record. Small amounts of payload data may be read
ahead. `DirectoryEntry::record_range` exposes the declared member span for
caller-controlled prefetching, before local validation.

Targets PKWARE APPNOTE 6.3.3 with stored/DEFLATE entries and UTF-8 names/comments.
Encryption, signatures, patched data, multi-volume archives, ZIP64 version-2
directories, and bytes outside declared records are rejected when the affected
records are checked. Listing alone does not validate unselected local records.
