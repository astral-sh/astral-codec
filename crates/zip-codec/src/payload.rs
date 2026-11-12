#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;
use std::io;

use flate2::{Crc, Decompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt};
use zip_framing::{CompressionMethod, Entry};

use crate::decode::DecodeError;

pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

pub(crate) struct Payload {
    integrity: Integrity,
    encoded_remaining: u64,
    encoding: Encoding,
}

enum Encoding {
    Stored,
    Deflate(Box<DeflateState>),
}

struct DeflateState {
    decoder: Decompress,
    input: Vec<u8>,
    consumed: usize,
    available: usize,
}

impl DeflateState {
    fn new(compressed_size: u64) -> Self {
        Self {
            decoder: Decompress::new(false),
            input: vec![0; compressed_size.min(CHUNK_SIZE as u64) as usize],
            consumed: 0,
            available: 0,
        }
    }
}

struct Integrity {
    position: u64,
    expected_crc: u32,
    crc: Crc,
    decoded_remaining: u64,
    done: bool,
}

impl Payload {
    pub(crate) fn new(entry: &Entry<'_>, previous: Option<Self>) -> Result<Self, DecodeError> {
        let directory = entry.directory();
        let encoding = match (directory.method(), previous.map(|payload| payload.encoding)) {
            (CompressionMethod::Stored, _) => Encoding::Stored,
            (CompressionMethod::Deflate, Some(Encoding::Deflate(mut state))) => {
                state.decoder.reset(false);
                let length = directory.compressed_size().min(CHUNK_SIZE as u64) as usize;
                if state.input.len() < length {
                    state.input.resize(length, 0);
                }
                state.consumed = 0;
                state.available = 0;
                Encoding::Deflate(state)
            }
            (CompressionMethod::Deflate, _) => {
                Encoding::Deflate(Box::new(DeflateState::new(directory.compressed_size())))
            }
            _ => {
                return Err(DecodeError::Unsupported {
                    position: directory.position(),
                    feature: "compression method",
                });
            }
        };

        Ok(Self {
            integrity: Integrity {
                position: directory.position(),
                expected_crc: directory.crc32(),
                crc: Crc::new(),
                decoded_remaining: directory.size(),
                done: false,
            },
            encoded_remaining: directory.compressed_size(),
            encoding,
        })
    }

    pub(crate) async fn read_to_end<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        output: &mut Vec<u8>,
    ) -> Result<usize, DecodeError> {
        let start = output.len();
        if self.integrity.decoded_remaining > CHUNK_SIZE as u64
            && (matches!(self.encoding, Encoding::Deflate(_))
                || output.capacity() - output.len() < CHUNK_SIZE)
        {
            // Reuse an existing destination when it can hold the first Stored
            // chunk. Otherwise keep checksum work in a reusable chunk while it
            // grows. DEFLATE also reuses initialized storage instead of zeroing
            // each new part of the destination.
            let mut chunk = Vec::new();
            while self
                .next::<false, _>(reader, &mut chunk, CHUNK_SIZE)
                .await?
            {
                output.extend_from_slice(&chunk);
            }
        } else {
            while self.next::<true, _>(reader, output, CHUNK_SIZE).await? {}
        }
        Ok(output.len() - start)
    }

    pub(crate) async fn next<const APPEND: bool, R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        output: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, DecodeError> {
        if target_len == 0 {
            return Err(self.integrity.invalid("zero payload chunk target"));
        }

        if self.integrity.done {
            return Ok(false);
        }

        // Empty ZIP members contain no file data, including when the method
        // field names DEFLATE. No decoder invocation is needed in that case.
        if self.encoded_remaining == 0
            && self.integrity.decoded_remaining == 0
            && !matches!(&self.encoding, Encoding::Deflate(state) if state.available != 0)
        {
            self.integrity.finish()?;
            return Ok(false);
        }

        tokio::task::consume_budget().await;

        // Leave one maximum DEFLATE match of output slack so its fast loop can
        // finish the stream. Integrity checks reject any excess before yielding
        // bytes, and every decoder call still respects the chunk target.
        let length = (target_len.min(CHUNK_SIZE) as u64)
            .min(self.integrity.decoded_remaining.saturating_add(258))
            as usize;
        let previous_length = output.len();
        let offset = if APPEND { previous_length } else { 0 };
        match &mut self.encoding {
            Encoding::Stored => {
                let length = (length as u64).min(self.encoded_remaining) as usize;
                if length == 0 {
                    return Err(self.integrity.invalid("stored payload ended early"));
                }

                if !APPEND {
                    output.clear();
                }
                output.reserve(length);
                let mut bounded = (&mut *reader).take(length as u64);
                while bounded.limit() != 0 {
                    if bounded.read_buf(output).await? == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                    }
                }

                self.encoded_remaining -= length as u64;
                self.integrity.account(&output[offset..])?;
                if self.encoded_remaining == 0 {
                    self.integrity.finish()?;
                }

                Ok(true)
            }
            Encoding::Deflate(state) => loop {
                if state.consumed == state.available && self.encoded_remaining != 0 {
                    let length = self.encoded_remaining.min(CHUNK_SIZE as u64) as usize;
                    reader.read_exact(&mut state.input[..length]).await?;
                    self.encoded_remaining -= length as u64;
                    state.consumed = 0;
                    state.available = length;
                }

                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| self.integrity.invalid("payload buffer length overflow"))?;
                // Never shrink before decompression: zero output must preserve
                // the caller's initialized bytes at a successful EOF.
                if output.len() < end {
                    output.resize(end, 0);
                }

                let before_input = state.decoder.total_in();
                let before_output = state.decoder.total_out();
                // A final bounded call needs no saved history when both the
                // remaining input and an overflow-detection byte fit.
                let flush = if self.encoded_remaining == 0
                    && self.integrity.decoded_remaining < length as u64
                {
                    FlushDecompress::Finish
                } else {
                    FlushDecompress::None
                };
                let status = state
                    .decoder
                    .decompress(
                        &state.input[state.consumed..state.available],
                        &mut output[offset..end],
                        flush,
                    )
                    .map_err(|_| self.integrity.invalid("invalid DEFLATE stream"))?;

                let consumed = (state.decoder.total_in() - before_input) as usize;
                let produced = (state.decoder.total_out() - before_output) as usize;
                state.consumed += consumed;
                self.integrity.account(&output[offset..offset + produced])?;

                if status == Status::StreamEnd {
                    if self.encoded_remaining != 0 || state.consumed != state.available {
                        return Err(self
                            .integrity
                            .invalid("trailing bytes after DEFLATE stream"));
                    }

                    self.integrity.finish()?;
                } else if consumed == 0 && produced == 0 {
                    return Err(self
                        .integrity
                        .invalid("truncated or stalled DEFLATE stream"));
                }

                if produced != 0 {
                    output.truncate(offset + produced);
                    return Ok(true);
                }

                if self.integrity.done {
                    output.truncate(previous_length);
                    return Ok(false);
                }

                // A hostile stream can consume many empty blocks without emitting
                // output. Bound each decoder call and give the executor a turn.
                tokio::task::consume_budget().await;
            },
        }
    }
}

impl Integrity {
    fn account(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.decoded_remaining = self
            .decoded_remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| self.invalid("decoded payload exceeds declared size"))?;
        update_crc(&mut self.crc, bytes);

        Ok(())
    }

    fn finish(&mut self) -> Result<(), DecodeError> {
        if self.decoded_remaining != 0 {
            return Err(self.invalid("decoded payload is shorter than declared size"));
        }

        if self.crc.sum() != self.expected_crc {
            return Err(self.invalid("payload CRC mismatch"));
        }

        self.done = true;

        Ok(())
    }

    fn invalid(&self, reason: &'static str) -> DecodeError {
        DecodeError::Integrity {
            position: self.position,
            reason,
        }
    }
}

fn update_crc(crc: &mut Crc, bytes: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if (4096..19200).contains(&bytes.len()) && is_aarch64_feature_detected!("crc") {
        // The backend interleaves hardware CRC chains only above 19,200 bytes.
        // Alternate two independent chains for medium buffers, leaving small
        // inputs and the backend's large-buffer path alone. Process the first
        // segment's remainder before combining the checksums in byte order.
        let length = bytes.len() / 512 * 256;
        let (first, second) = bytes.split_at(bytes.len() - length);
        let mut additional = Crc::new();
        for (first, second) in first[..length]
            .as_chunks::<256>()
            .0
            .iter()
            .zip(second.as_chunks::<256>().0)
        {
            crc.update(first);
            additional.update(second);
        }
        crc.update(&first[length..]);
        crc.combine(&additional);
        return;
    }
    crc.update(bytes);
}

#[cfg(test)]
mod tests {
    use flate2::Crc;

    use super::{CHUNK_SIZE, update_crc};

    #[test]
    fn checksum_updates_match_contiguous_bytes() {
        let mut state = 0x1234_5678u32;
        let bytes: Vec<_> = (0..CHUNK_SIZE + 8)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        // Cover both fast-path thresholds, partial interleaved blocks, source
        // alignment, and updates before and after an interleaved checksum.
        for length in [
            0, 1, 63, 64, 255, 256, 511, 512, 4095, 4096, 4097, 4351, 4352, 4353, 8191, 8192, 8193,
            19199, 19200, 19201, CHUNK_SIZE,
        ] {
            for alignment in 0..8 {
                for prefix in [&b""[..], &bytes[..37]] {
                    let mut actual = Crc::new();
                    let mut expected = crc32fast::Hasher::new();
                    for part in [prefix, &bytes[alignment..alignment + length], &bytes[..73]] {
                        update_crc(&mut actual, part);
                        expected.update(part);
                        assert_eq!(actual.sum(), expected.clone().finalize());
                    }
                    assert_eq!(actual.amount() as usize, prefix.len() + length + 73);
                }
            }
        }
    }
}
