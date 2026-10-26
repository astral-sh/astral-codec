use std::{fmt, hint::black_box, sync::Arc};

use divan::{Bencher, counter::ItemsCount};
use tar_codec::{
    Archive as _, DecodePolicy, Member, MemberPayload as _, PaxDecodePolicy,
    PaxVendorExtensionPolicy, PaxVendorValue, TarArchive,
};
use tar_framing::{PaxKeyword, write::append_pax_record};
use tokio::runtime::Builder as RuntimeBuilder;

const MEMBER_COUNT: usize = 1024;
const PAYLOAD_SIZE: usize = 64;
const VALUE_SIZE: usize = 64;

#[derive(Clone, Copy)]
enum Case {
    Plain,
    Local(usize),
    Global(usize),
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => write!(formatter, "plain-{MEMBER_COUNT}-members"),
            Self::Local(records) => {
                write!(formatter, "local-{records}-records-{MEMBER_COUNT}-members")
            }
            Self::Global(records) => {
                write!(formatter, "global-{records}-records-{MEMBER_COUNT}-members")
            }
        }
    }
}

fn cases() -> [Case; 4] {
    [
        Case::Plain,
        Case::Local(4),
        Case::Global(64),
        Case::Global(512),
    ]
}

fn vendor_cases() -> [Case; 3] {
    [Case::Local(4), Case::Global(64), Case::Global(512)]
}

fn append_member(
    builder: &mut tar::Builder<Vec<u8>>,
    name: &str,
    entry_type: tar::EntryType,
    payload: &[u8],
) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(entry_type);
    header.set_size(u64::try_from(payload.len()).expect("fixture payload should fit in u64"));
    header.set_mode(0o644);
    header.set_mtime(1_704_164_645);
    header.set_cksum();
    builder
        .append_data(&mut header, name, payload)
        .expect("fixture member should be encoded");
}

fn fixture(case: Case) -> Vec<u8> {
    let mut records = Vec::new();
    if let Case::Local(count) | Case::Global(count) = case {
        for index in 0..count {
            append_pax_record(
                &mut records,
                &PaxKeyword::Vendor {
                    vendor: Arc::from("Acme"),
                    name: Arc::from(format!("attribute-{index}")),
                },
                &[b'v'; VALUE_SIZE],
            )
            .expect("fixture vendor record should be encoded");
        }
    }
    let mut builder = tar::Builder::new(Vec::new());
    if matches!(case, Case::Global(_)) {
        append_member(&mut builder, "pax", tar::EntryType::XGlobalHeader, &records);
    }
    for index in 0..MEMBER_COUNT {
        if matches!(case, Case::Local(_)) {
            append_member(&mut builder, "pax", tar::EntryType::XHeader, &records);
        }
        append_member(
            &mut builder,
            &format!("member-{index}"),
            tar::EntryType::Regular,
            &[b'p'; PAYLOAD_SIZE],
        );
    }
    builder.into_inner().expect("fixture archive should finish")
}

async fn decode_without_reading_metadata(input: &[u8], case: Case) -> usize {
    let mut archive = TarArchive::new(input);
    if !matches!(case, Case::Plain) {
        archive = archive.with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        );
    }
    let mut members = archive.members();
    let mut payload_bytes = 0;
    while let Some(member) = members.next().await.expect("fixture member should decode") {
        if let Member::File { size, payload, .. } = member {
            payload_bytes += usize::try_from(size).expect("fixture size should fit in usize");
            payload
                .skip()
                .await
                .expect("fixture payload should validate");
        }
    }
    assert_eq!(payload_bytes, MEMBER_COUNT * PAYLOAD_SIZE);
    payload_bytes
}

async fn decode_and_read_metadata(input: &[u8]) -> (usize, usize) {
    let mut members = TarArchive::new(input)
        .retain_pax_vendor_records(true)
        .with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        )
        .members();
    let mut payload_bytes = 0;
    let mut metadata_bytes = 0;
    while let Some(member) = members.next().await.expect("fixture member should decode") {
        if let Member::File {
            metadata,
            size,
            payload,
            ..
        } = member
        {
            for (key, value) in metadata.pax_vendor_records.iter() {
                if let PaxVendorValue::Value(value) = value {
                    metadata_bytes += key.len() + value.len();
                    black_box(value);
                }
            }
            payload_bytes += usize::try_from(size).expect("fixture size should fit in usize");
            payload
                .skip()
                .await
                .expect("fixture payload should validate");
        }
    }
    assert_eq!(payload_bytes, MEMBER_COUNT * PAYLOAD_SIZE);
    (payload_bytes, metadata_bytes)
}

#[divan::bench(args = cases(), sample_size = 1)]
fn ignore_metadata(bencher: Bencher, case: &Case) {
    let runtime = RuntimeBuilder::new_current_thread()
        .build()
        .expect("benchmark runtime should be created");
    let input = fixture(*case);
    bencher
        .counter(ItemsCount::new(MEMBER_COUNT))
        .bench_local(|| {
            black_box(runtime.block_on(decode_without_reading_metadata(
                black_box(input.as_slice()),
                *case,
            )));
        });
}

#[divan::bench(args = vendor_cases(), sample_size = 1)]
fn read_metadata(bencher: Bencher, case: &Case) {
    let runtime = RuntimeBuilder::new_current_thread()
        .build()
        .expect("benchmark runtime should be created");
    let input = fixture(*case);
    let record_count = match case {
        Case::Local(count) | Case::Global(count) => *count,
        Case::Plain => 0,
    };
    let expected_metadata_bytes = (0..record_count)
        .map(|index| format!("Acme.attribute-{index}").len() + VALUE_SIZE)
        .sum::<usize>()
        * MEMBER_COUNT;
    bencher
        .counter(ItemsCount::new(MEMBER_COUNT))
        .bench_local(|| {
            let result = runtime.block_on(decode_and_read_metadata(black_box(input.as_slice())));
            assert_eq!(result.1, expected_metadata_bytes);
            black_box(result);
        });
}

fn main() {
    divan::main();
}
