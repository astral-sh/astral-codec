# zip-framing

Asynchronous, bounded indexing of seekable ZIP archives. `Index::read` checks
the central directory; `Index::entry` reconciles a selected local header,
ZIP64 extensions, and data descriptor before returning a checked `Entry`.
Resolution also interprets host-specific attributes and checks kind-specific
metadata. `Entry::kind()` returns the cached `EntryKind`; `Entry::unix_mode()`
preserves the Unix file type and permission bits. `Index::validate_all` checks
complete physical coverage, redundant metadata, and member kinds, including
unselected members. Payload integrity and compression belong to `zip-codec`.

Kinds include volume labels, sockets, and unknown Unix types even though
`zip-codec` cannot project them. `Entry::unix_data()` returns typed
`UnixData`, including UTF-8 link targets without NUL bytes and decoded device
numbers. Symbolic links can also store targets in their payloads, which the
codec decodes and validates. The symbolic-link size limit belongs to the codec.

Directory reads use a bounded 64 KiB window; selected local records use a 4 KiB
window bounded by the next record. Small amounts of payload data may be read
ahead. `IndexedEntry::record_range` exposes the declared member span for
caller-controlled prefetching, before local validation. `IndexedEntry::directory`
provides the metadata declared by the central directory.

Targets PKWARE APPNOTE 6.3.3 with stored/DEFLATE entries and UTF-8 names/comments.
Encryption, signatures, patched data, multi-volume archives, ZIP64 version-2
directories, and bytes outside declared records are rejected when the affected
records are checked. Listing alone does not validate unselected local records.
