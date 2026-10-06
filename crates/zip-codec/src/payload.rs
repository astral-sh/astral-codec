use std::io;

use crc32fast::Hasher;
use flate2::{Decompress, FlushDecompress, Status};
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
    crc: Hasher,
    decoded_remaining: u64,
    done: bool,
}

impl Payload {
    pub(crate) fn new(entry: &Entry<'_>) -> Result<Self, DecodeError> {
        let directory = entry.directory();
        let encoding = match directory.method() {
            CompressionMethod::Stored => Encoding::Stored,
            CompressionMethod::Deflate => {
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
                crc: Hasher::new(),
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
        if matches!(self.encoding, Encoding::Deflate(_))
            && self.integrity.decoded_remaining > CHUNK_SIZE as u64
        {
            // Reuse initialized storage across decoder calls instead of zeroing
            // every new part of a large collection buffer before overwriting it.
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

        let length = (target_len.min(CHUNK_SIZE) as u64)
            .min(self.integrity.decoded_remaining.saturating_add(1)) as usize;
        let previous_length = output.len();
        let offset = if APPEND { previous_length } else { 0 };
        match &mut self.encoding {
            Encoding::Stored => {
                let length = (length as u64).min(self.encoded_remaining) as usize;
                if length == 0 {
                    return Err(self.integrity.invalid("stored payload ended early"));
                }

                if APPEND {
                    output.reserve(length);
                    let mut bounded = (&mut *reader).take(length as u64);
                    while bounded.limit() != 0 {
                        if bounded.read_buf(output).await? == 0 {
                            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                        }
                    }
                } else {
                    output.resize(length, 0);
                    reader.read_exact(output).await?;
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
                let status = state
                    .decoder
                    .decompress(
                        &state.input[state.consumed..state.available],
                        &mut output[offset..end],
                        FlushDecompress::None,
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
        self.crc.update(bytes);

        Ok(())
    }

    fn finish(&mut self) -> Result<(), DecodeError> {
        if self.decoded_remaining != 0 {
            return Err(self.invalid("decoded payload is shorter than declared size"));
        }

        if self.crc.clone().finalize() != self.expected_crc {
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
