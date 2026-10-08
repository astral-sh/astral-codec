use std::{fmt, fs, io::Cursor, path::PathBuf};

use serde::Deserialize;
use tokio::runtime::{Builder, Runtime};
use zip::ZipArchive;

#[derive(Clone, Copy)]
pub(super) enum Implementation {
    ZipCodec,
    Zip,
    AsyncZip,
}

impl fmt::Display for Implementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZipCodec => "zip-codec",
            Self::Zip => "zip",
            Self::AsyncZip => "astral_async_zip",
        })
    }
}

pub(super) struct Case {
    pub(super) name: &'static str,
    pub(super) implementation: Implementation,
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.name, self.implementation)
    }
}

#[derive(Deserialize)]
struct Wheel<'a> {
    name: &'a str,
}

pub(super) fn cases() -> impl Iterator<Item = Case> {
    serde_json::from_str::<Vec<Wheel<'static>>>(include_str!("corpus.json"))
        .expect("valid wheel corpus")
        .into_iter()
        .flat_map(|wheel| {
            [
                Implementation::ZipCodec,
                Implementation::Zip,
                Implementation::AsyncZip,
            ]
            .into_iter()
            .map(move |implementation| Case {
                name: wheel.name,
                implementation,
            })
        })
}

pub(super) fn runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime should build")
}

pub(super) struct Entry {
    pub(super) path: String,
    pub(super) directory: bool,
    pub(super) size: u64,
    pub(super) crc: u32,
}

pub(super) struct Fixture {
    pub(super) bytes: Vec<u8>,
    pub(super) entries: Vec<Entry>,
    pub(super) payload_bytes: u64,
}

impl Fixture {
    pub(super) fn load(case: &Case) -> Self {
        let root = std::env::var_os("WHEEL_CORPUS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/wheel-corpus")
            });
        let bytes = fs::read(root.join(format!("{}.whl", case.name)))
            .expect("wheel missing; run: uv run --locked crates/zip-codec/benches/wheels/fetch.py");
        let mut archive = ZipArchive::new(Cursor::new(&bytes)).expect("pinned wheel should open");
        let entries: Vec<_> = (0..archive.len())
            .map(|index| {
                let entry = archive.by_index(index).expect("pinned wheel entry");
                // The async-zip extraction helper below only receives these
                // pinned, pre-checked paths; it is not a general-purpose extractor.
                assert!(entry.enclosed_name().is_some(), "invalid corpus path");
                Entry {
                    path: entry.name().to_owned(),
                    directory: entry.is_dir(),
                    size: entry.size(),
                    crc: entry.crc32(),
                }
            })
            .collect();
        let payload_bytes = entries.iter().map(|entry| entry.size).sum();
        Self {
            bytes,
            entries,
            payload_bytes,
        }
    }
}
