use std::mem;

use flate2::{Crc, Decompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt};
use zip_framing::{CompressionMethod, Entry};

use crate::decode::DecodeError;

pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

pub(crate) struct Payload {
    position: u64,
    expected_crc: u32,
    crc: Crc,
    encoded_remaining: u64,
    decoded_remaining: u64,
    decoder: Option<Decompress>,
    input: Vec<u8>,
    output: Vec<u8>,
    consumed: usize,
    available: usize,
    done: bool,
}

impl Payload {
    pub(crate) fn new(entry: &Entry) -> Result<Self, DecodeError> {
        let decoder = match entry.method() {
            CompressionMethod::Stored => None,
            CompressionMethod::Deflate => Some(Decompress::new(false)),
            _ => {
                return Err(DecodeError::Unsupported {
                    position: entry.position(),
                    feature: "compression method",
                });
            }
        };
        Ok(Self {
            position: entry.position(),
            expected_crc: entry.crc32(),
            crc: Crc::new(),
            encoded_remaining: entry.compressed_size(),
            decoded_remaining: entry.size(),
            decoder,
            input: vec![0; CHUNK_SIZE],
            output: Vec::new(),
            consumed: 0,
            available: 0,
            done: false,
        })
    }

    pub(crate) async fn next<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        output: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, DecodeError> {
        if target_len == 0 {
            return Err(self.invalid("zero payload chunk target"));
        }
        if self.done {
            return Ok(false);
        }
        // Empty ZIP members contain no file data, including when the method
        // field names DEFLATE. No decoder invocation is needed in that case.
        if self.encoded_remaining == 0 && self.decoded_remaining == 0 && self.available == 0 {
            self.finish()?;
            return Ok(false);
        }
        tokio::task::yield_now().await;
        let length = (target_len.min(CHUNK_SIZE) as u64)
            .min(self.decoded_remaining.saturating_add(1)) as usize;
        if self.decoder.is_none() {
            let length = (length as u64).min(self.encoded_remaining) as usize;
            if length == 0 {
                return Err(self.invalid("stored payload ended early"));
            }
            output.resize(length, 0);
            reader.read_exact(output).await?;
            self.encoded_remaining -= length as u64;
            self.account(output)?;
            if self.encoded_remaining == 0 {
                self.finish()?;
            }
            return Ok(true);
        }

        loop {
            if self.consumed == self.available && self.encoded_remaining != 0 {
                let length = self.encoded_remaining.min(CHUNK_SIZE as u64) as usize;
                reader.read_exact(&mut self.input[..length]).await?;
                self.encoded_remaining -= length as u64;
                self.consumed = 0;
                self.available = length;
            }
            // Use a separate output buffer until nonempty output is available,
            // preserving MemberPayload's buffer contract on a successful EOF.
            let mut decoded = mem::take(&mut self.output);
            decoded.resize(length, 0);
            let Some(decoder) = &mut self.decoder else {
                return Err(self.invalid("missing DEFLATE state"));
            };
            let before_input = decoder.total_in();
            let before_output = decoder.total_out();
            let status = decoder
                .decompress(
                    &self.input[self.consumed..self.available],
                    &mut decoded,
                    FlushDecompress::None,
                )
                .map_err(|_| DecodeError::Integrity {
                    position: self.position,
                    reason: "invalid DEFLATE stream",
                })?;
            let consumed = (decoder.total_in() - before_input) as usize;
            let produced = (decoder.total_out() - before_output) as usize;
            self.consumed += consumed;
            decoded.truncate(produced);
            self.account(&decoded)?;
            if status == Status::StreamEnd {
                if self.encoded_remaining != 0 || self.consumed != self.available {
                    return Err(self.invalid("trailing bytes after DEFLATE stream"));
                }
                self.finish()?;
            } else if consumed == 0 && produced == 0 {
                return Err(self.invalid("truncated or stalled DEFLATE stream"));
            }
            if produced != 0 {
                mem::swap(output, &mut decoded);
                self.output = decoded;
                return Ok(true);
            }
            self.output = decoded;
            if self.done {
                return Ok(false);
            }
            // A hostile stream can consume many empty blocks without emitting
            // output. Bound each decoder call and give the executor a turn.
            tokio::task::yield_now().await;
        }
    }

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
