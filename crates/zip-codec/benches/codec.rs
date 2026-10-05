mod support;

use std::{hint::black_box, io::Cursor};

use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use zip_codec::{Archive, Member, MemberPayload, ZipArchive};

use support::{Case, PAYLOAD_CHUNK_BYTES, cases, encode_archive, fixture, runtime};

async fn decode_members(archive: &mut ZipArchive<Cursor<&[u8]>>) -> (usize, u64) {
    let mut entries = 0;
    let mut payload_bytes = 0;
    let mut chunk = Vec::new();
    while let Some(Member::File { mut payload, .. }) = archive
        .next_member()
        .await
        .expect("fixture member should decode")
    {
        entries += 1;
        while payload
            .next_chunk(&mut chunk, PAYLOAD_CHUNK_BYTES)
            .await
            .expect("fixture payload should decode")
        {
            payload_bytes += black_box(&chunk).len() as u64;
        }
    }
    (entries, payload_bytes)
}

#[divan::bench(args = cases())]
fn encode(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(case, &runtime);
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        .bench_local(|| {
            black_box(runtime.block_on(encode_archive(black_box(&fixture.entries), case.method)));
        });
}

#[divan::bench(args = cases(), sample_size = 1)]
fn decode_payload(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(case, &runtime);
    let mut archive = runtime
        .block_on(ZipArchive::open(Cursor::new(fixture.archive.as_slice())))
        .expect("fixture archive should open");
    assert_eq!(
        runtime.block_on(decode_members(&mut archive)),
        (fixture.entries.len(), fixture.payload_bytes)
    );
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        // Directory indexing is measured separately in zip-framing. Each input
        // starts with unresolved local records and unread payloads.
        .with_inputs(|| {
            runtime
                .block_on(ZipArchive::open(Cursor::new(fixture.archive.as_slice())))
                .expect("fixture archive should open")
        })
        .bench_local_refs(|archive| {
            black_box(runtime.block_on(decode_members(black_box(archive))));
        });
}

fn main() {
    divan::main();
}
