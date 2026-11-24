//! Incremental bounded streaming HTTP body reader enforcing both compressed AND decompressed
//! byte budgets (default 16 MiB; rejects 60 MiB zip-bomb payloads in bounded memory).

use std::io::{self, Write};

use flate2::write::{DeflateDecoder, GzDecoder, ZlibDecoder};
use futures::StreamExt;
use http::HeaderMap;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use n8n_types::{N8nError, N8nResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default response stream cap: 16 MiB (16,777,216 bytes) for both compressed and decompressed bytes.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StreamBudget {
    pub max_compressed_bytes: u64,
    pub max_decompressed_bytes: u64,
}

impl Default for StreamBudget {
    fn default() -> Self {
        Self {
            max_compressed_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_decompressed_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

struct BoundedVecWriter {
    buf: Vec<u8>,
    max_bytes: u64,
    attempted_bytes: u64,
}

impl BoundedVecWriter {
    fn new(max_bytes: u64, initial_capacity: usize) -> Self {
        let capped_cap = initial_capacity.min(usize::try_from(max_bytes).unwrap_or(usize::MAX));
        Self {
            buf: Vec::with_capacity(capped_cap.min(64 * 1024)),
            max_bytes,
            attempted_bytes: 0,
        }
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.attempted_bytes = self.attempted_bytes.saturating_add(data.len() as u64);
        if self.attempted_bytes > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "decompressed payload exceeded byte budget",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentCodec {
    Identity,
    Gzip,
    Zlib,
    DeflateRaw,
    Zstd,
}

fn parse_content_codec(headers: &HeaderMap) -> N8nResult<ContentCodec> {
    let Some(raw) = headers.get(CONTENT_ENCODING) else {
        return Ok(ContentCodec::Identity);
    };
    let enc = raw
        .to_str()
        .map_err(|_| N8nError::protocol("non-ASCII Content-Encoding header"))?
        .trim()
        .to_ascii_lowercase();
    match enc.as_str() {
        "" | "identity" => Ok(ContentCodec::Identity),
        "gzip" | "x-gzip" => Ok(ContentCodec::Gzip),
        "deflate" => Ok(ContentCodec::Zlib),
        "x-deflate" => Ok(ContentCodec::DeflateRaw),
        "zstd" => Ok(ContentCodec::Zstd),
        other => Err(N8nError::protocol(format!(
            "unsupported Content-Encoding `{other}`"
        ))),
    }
}

/// Streams a `reqwest::Response` incrementally, enforcing both `budget.max_compressed_bytes` on the
/// wire stream and `budget.max_decompressed_bytes` on the decoded output.
pub async fn read_bounded_response(
    instance: &str,
    response: reqwest::Response,
    budget: StreamBudget,
) -> N8nResult<Vec<u8>> {
    let headers = response.headers();
    if let Some(len_val) = headers.get(CONTENT_LENGTH)
        && let Ok(len_str) = len_val.to_str()
        && let Ok(declared_len) = len_str.trim().parse::<u64>()
        && declared_len > budget.max_compressed_bytes
    {
        return Err(N8nError::payload_too_large(
            budget.max_compressed_bytes,
            declared_len,
            "compressed_content_length",
        ));
    }

    let codec = parse_content_codec(headers)?;
    let mut stream = response.bytes_stream();
    let mut compressed_seen: u64 = 0;

    match codec {
        ContentCodec::Identity => {
            let mut out = BoundedVecWriter::new(budget.max_decompressed_bytes, 8192);
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    N8nError::transport(
                        instance,
                        None,
                        format!("error reading response stream: {e}"),
                    )
                })?;
                compressed_seen = compressed_seen.saturating_add(chunk.len() as u64);
                if compressed_seen > budget.max_compressed_bytes {
                    return Err(N8nError::payload_too_large(
                        budget.max_compressed_bytes,
                        compressed_seen,
                        "compressed",
                    ));
                }
                if out.write_all(&chunk).is_err() {
                    return Err(N8nError::payload_too_large(
                        budget.max_decompressed_bytes,
                        out.attempted_bytes,
                        "decompressed",
                    ));
                }
            }
            Ok(out.buf)
        }
        ContentCodec::Gzip => {
            let mut decoder =
                GzDecoder::new(BoundedVecWriter::new(budget.max_decompressed_bytes, 16384));
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    N8nError::transport(instance, None, format!("error reading gzip stream: {e}"))
                })?;
                compressed_seen = compressed_seen.saturating_add(chunk.len() as u64);
                if compressed_seen > budget.max_compressed_bytes {
                    return Err(N8nError::payload_too_large(
                        budget.max_compressed_bytes,
                        compressed_seen,
                        "compressed",
                    ));
                }
                if let Err(err) = decoder.write_all(&chunk) {
                    if err.kind() == io::ErrorKind::FileTooLarge {
                        let observed = decoder.get_ref().attempted_bytes;
                        return Err(N8nError::payload_too_large(
                            budget.max_decompressed_bytes,
                            observed,
                            "decompressed",
                        ));
                    }
                    return Err(N8nError::protocol(format!("invalid gzip payload: {err}")));
                }
            }
            match decoder.finish() {
                Ok(writer) => Ok(writer.buf),
                Err(err) if err.kind() == io::ErrorKind::FileTooLarge => {
                    Err(N8nError::payload_too_large(
                        budget.max_decompressed_bytes,
                        budget.max_decompressed_bytes + 1,
                        "decompressed",
                    ))
                }
                Err(err) => Err(N8nError::protocol(format!(
                    "truncated or corrupt gzip payload: {err}"
                ))),
            }
        }
        ContentCodec::Zlib => {
            let mut decoder =
                ZlibDecoder::new(BoundedVecWriter::new(budget.max_decompressed_bytes, 16384));
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    N8nError::transport(
                        instance,
                        None,
                        format!("error reading deflate stream: {e}"),
                    )
                })?;
                compressed_seen = compressed_seen.saturating_add(chunk.len() as u64);
                if compressed_seen > budget.max_compressed_bytes {
                    return Err(N8nError::payload_too_large(
                        budget.max_compressed_bytes,
                        compressed_seen,
                        "compressed",
                    ));
                }
                if let Err(err) = decoder.write_all(&chunk) {
                    if err.kind() == io::ErrorKind::FileTooLarge {
                        let observed = decoder.get_ref().attempted_bytes;
                        return Err(N8nError::payload_too_large(
                            budget.max_decompressed_bytes,
                            observed,
                            "decompressed",
                        ));
                    }
                    return Err(N8nError::protocol(format!(
                        "invalid deflate payload: {err}"
                    )));
                }
            }
            match decoder.finish() {
                Ok(writer) => Ok(writer.buf),
                Err(err) if err.kind() == io::ErrorKind::FileTooLarge => {
                    Err(N8nError::payload_too_large(
                        budget.max_decompressed_bytes,
                        budget.max_decompressed_bytes + 1,
                        "decompressed",
                    ))
                }
                Err(err) => Err(N8nError::protocol(format!(
                    "truncated or corrupt deflate payload: {err}"
                ))),
            }
        }
        ContentCodec::DeflateRaw => {
            let mut decoder =
                DeflateDecoder::new(BoundedVecWriter::new(budget.max_decompressed_bytes, 16384));
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    N8nError::transport(
                        instance,
                        None,
                        format!("error reading raw deflate stream: {e}"),
                    )
                })?;
                compressed_seen = compressed_seen.saturating_add(chunk.len() as u64);
                if compressed_seen > budget.max_compressed_bytes {
                    return Err(N8nError::payload_too_large(
                        budget.max_compressed_bytes,
                        compressed_seen,
                        "compressed",
                    ));
                }
                if let Err(err) = decoder.write_all(&chunk) {
                    if err.kind() == io::ErrorKind::FileTooLarge {
                        let observed = decoder.get_ref().attempted_bytes;
                        return Err(N8nError::payload_too_large(
                            budget.max_decompressed_bytes,
                            observed,
                            "decompressed",
                        ));
                    }
                    return Err(N8nError::protocol(format!(
                        "invalid raw deflate payload: {err}"
                    )));
                }
            }
            match decoder.finish() {
                Ok(writer) => Ok(writer.buf),
                Err(err) if err.kind() == io::ErrorKind::FileTooLarge => {
                    Err(N8nError::payload_too_large(
                        budget.max_decompressed_bytes,
                        budget.max_decompressed_bytes + 1,
                        "decompressed",
                    ))
                }
                Err(err) => Err(N8nError::protocol(format!(
                    "truncated or corrupt raw deflate payload: {err}"
                ))),
            }
        }
        ContentCodec::Zstd => {
            let mut decoder = zstd::stream::write::Decoder::new(BoundedVecWriter::new(
                budget.max_decompressed_bytes,
                16384,
            ))
            .map_err(|e| N8nError::protocol(format!("failed initializing zstd decoder: {e}")))?;
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| {
                    N8nError::transport(instance, None, format!("error reading zstd stream: {e}"))
                })?;
                compressed_seen = compressed_seen.saturating_add(chunk.len() as u64);
                if compressed_seen > budget.max_compressed_bytes {
                    return Err(N8nError::payload_too_large(
                        budget.max_compressed_bytes,
                        compressed_seen,
                        "compressed",
                    ));
                }
                if let Err(err) = decoder.write_all(&chunk) {
                    if err.kind() == io::ErrorKind::FileTooLarge {
                        let observed = decoder.get_ref().attempted_bytes;
                        return Err(N8nError::payload_too_large(
                            budget.max_decompressed_bytes,
                            observed,
                            "decompressed",
                        ));
                    }
                    return Err(N8nError::protocol(format!("invalid zstd payload: {err}")));
                }
            }
            if let Err(err) = decoder.flush() {
                if err.kind() == io::ErrorKind::FileTooLarge {
                    let observed = decoder.get_ref().attempted_bytes;
                    return Err(N8nError::payload_too_large(
                        budget.max_decompressed_bytes,
                        observed,
                        "decompressed",
                    ));
                }
                return Err(N8nError::protocol(format!("corrupt zstd footer: {err}")));
            }
            Ok(decoder.into_inner().buf)
        }
    }
}
