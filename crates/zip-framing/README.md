# zip-framing

Asynchronous, bounded indexing of seekable ZIP archives. Validates the complete
physical layout and agreement between central headers, local headers, ZIP64
extensions, and data descriptors before returning an index. Payload integrity
and compression belong to `zip-codec`.

Targets PKWARE APPNOTE 6.3.3 with stored/DEFLATE entries and UTF-8 names. Encryption,
signatures, patched data, multi-volume archives, ZIP64 version-2 directories,
and bytes outside declared records are rejected.
