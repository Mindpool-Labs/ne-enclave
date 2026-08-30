// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Chunked streaming AES-256-GCM container for sealed `mem`/`vmstate` files.
//!
//! Layout:
//! ```text
//! magic        b"NESEAL01"   (8 bytes)
//! chunk_size   u32 BE
//! records...   [nonce(12)][len_be_u32][ciphertext(len)][tag(16)]
//! final        empty sentinel record (len=0, AD chunk_index = data chunk count)
//! ```
//! Each record's GCM AD = `b"ne-enclave-sealed-artifact-v1" || snapshot_id ||
//! manifest_canonical_sha256 || chunk_index_le(8)`. The sentinel is keyed to
//! the running data-chunk count (the value the encrypt loop's `index` reaches
//! after the last data chunk), so it only authenticates at true end-of-stream;
//! moving a non-empty stream's trailing sentinel to the front of a truncated
//! container yields a mismatched AD index and GCM auth fails. Each chunk's tag
//! is verified before its plaintext is emitted (never decrypt-before-auth).

use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand::RngCore;

use crate::SealError;

const AD_DOMAIN: &[u8] = b"ne-enclave-sealed-artifact-v1";
/// Magic header identifying a sealed artifact container.
pub const FILE_MAGIC: &[u8] = b"NESEAL01";
/// Per-chunk plaintext size.
pub const CHUNK_SIZE: usize = 1 << 20; // 1 MiB

fn ad_for(snapshot_id: &[u8], manifest_hash: &[u8], index: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_DOMAIN.len() + snapshot_id.len() + manifest_hash.len() + 8);
    ad.extend_from_slice(AD_DOMAIN);
    ad.extend_from_slice(snapshot_id);
    ad.extend_from_slice(manifest_hash);
    ad.extend_from_slice(&index.to_le_bytes());
    ad
}

fn write_u32_be<W: Write>(w: &mut W, v: u32) -> Result<(), SealError> {
    w.write_all(&v.to_be_bytes()).map_err(SealError::Io)
}

fn read_exact_u32_be<R: Read>(r: &mut R) -> Result<u32, SealError> {
    let mut buf = [0u8; 4];
    match r.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(SealError::CiphertextCorrupt);
        }
        Err(e) => return Err(SealError::Io(e)),
    }
    Ok(u32::from_be_bytes(buf))
}

/// Encrypt `reader` into `writer` under `dek`. Streams; does not buffer the
/// whole plaintext.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dek: &[u8; 32],
    snapshot_id: &str,
    manifest_hash: &str,
) -> Result<(), SealError> {
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|e| SealError::BadCrypto(e.to_string()))?;
    writer.write_all(FILE_MAGIC).map_err(SealError::Io)?;
    write_u32_be(
        writer,
        u32::try_from(CHUNK_SIZE).map_err(|e| SealError::BadCrypto(e.to_string()))?,
    )?;
    let sid = snapshot_id.as_bytes();
    let mh = manifest_hash.as_bytes();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut index: u64 = 0;
    loop {
        let n = read_fill(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        write_record(&cipher, writer, sid, mh, index, &buf[..n])?;
        index = index
            .checked_add(1)
            .ok_or_else(|| SealError::BadCrypto("chunk overflow".into()))?;
    }
    // Sentinel empty record authenticates end-of-stream. It is keyed to the
    // running data-chunk count (`index`) so a trailing sentinel moved to the
    // front of a truncated container authenticates with a mismatched AD index
    // and is rejected.
    write_record(&cipher, writer, sid, mh, index, &[])?;
    writer.flush().map_err(SealError::Io)
}

fn write_record<W: Write>(
    cipher: &Aes256Gcm,
    w: &mut W,
    sid: &[u8],
    mh: &[u8],
    index: u64,
    pt: &[u8],
) -> Result<(), SealError> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            &nonce.into(),
            aes_gcm::aead::Payload {
                msg: pt,
                aad: &ad_for(sid, mh, index),
            },
        )
        .map_err(|_| SealError::CiphertextCorrupt)?;
    w.write_all(&nonce).map_err(SealError::Io)?;
    write_u32_be(
        w,
        u32::try_from(pt.len()).map_err(|e| SealError::BadCrypto(e.to_string()))?,
    )?;
    w.write_all(&ct).map_err(SealError::Io)?; // ct includes the trailing 16-byte tag
    Ok(())
}

/// Decrypt `reader` into `writer`. Each chunk's tag is verified before its
/// plaintext is emitted.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dek: &[u8; 32],
    snapshot_id: &str,
    manifest_hash: &str,
) -> Result<(), SealError> {
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|e| SealError::BadCrypto(e.to_string()))?;
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).map_err(SealError::Io)?;
    if magic != FILE_MAGIC {
        return Err(SealError::CiphertextCorrupt);
    }
    let _chunk_size = read_exact_u32_be(reader)?;
    let sid = snapshot_id.as_bytes();
    let mh = manifest_hash.as_bytes();
    let mut expected_index: u64 = 0;
    loop {
        let mut nonce = [0u8; 12];
        match reader.read_exact(&mut nonce) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SealError::CiphertextCorrupt); // missing sentinel
            }
            Err(e) => return Err(SealError::Io(e)),
        }
        let len = read_exact_u32_be(reader)?;
        // DoS guard: an unauthenticated `len` must not drive a pre-auth
        // allocation. Legit data chunks are <= CHUNK_SIZE; the sentinel has
        // len == 0 and is handled below.
        if len != 0 && len as usize > CHUNK_SIZE {
            return Err(SealError::CiphertextCorrupt);
        }
        let mut ct = vec![0u8; len as usize + 16]; // ciphertext + tag
        match reader.read_exact(&mut ct) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SealError::CiphertextCorrupt); // truncated record
            }
            Err(e) => return Err(SealError::Io(e)),
        }
        // A `len == 0` record is the sentinel. Its AD index must equal the
        // running data-chunk count (`expected_index`); a front-moved sentinel
        // from a non-empty stream was encrypted at a higher index and will
        // fail GCM auth below -> CiphertextCorrupt.
        let index = expected_index;
        let pt = cipher
            .decrypt(
                &nonce.into(),
                aes_gcm::aead::Payload {
                    msg: &ct,
                    aad: &ad_for(sid, mh, index),
                },
            )
            .map_err(|_| SealError::CiphertextCorrupt)?;
        if len == 0 {
            return writer.flush().map_err(SealError::Io);
        }
        writer.write_all(&pt).map_err(SealError::Io)?;
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| SealError::BadCrypto("chunk overflow".into()))?;
    }
}

fn read_fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, SealError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).map_err(SealError::Io)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek() -> [u8; 32] {
        [42u8; 32]
    }

    fn roundtrip(plain: &[u8]) -> Vec<u8> {
        let mut enc: Vec<u8> = Vec::new();
        let mut r = plain;
        encrypt_stream(&mut r, &mut enc, &dek(), "01SNAP", "abcd").unwrap();
        let mut out: Vec<u8> = Vec::new();
        let mut reader = enc.as_slice();
        decrypt_stream(&mut reader, &mut out, &dek(), "01SNAP", "abcd").unwrap();
        out
    }

    #[test]
    fn roundtrips_various_sizes() {
        assert_eq!(roundtrip(&[]), &b""[..]);
        assert_eq!(roundtrip(b"hi"), &b"hi"[..]);
        assert_eq!(
            roundtrip(&vec![1u8; CHUNK_SIZE - 1]),
            &vec![1u8; CHUNK_SIZE - 1][..]
        );
        assert_eq!(
            roundtrip(&vec![2u8; CHUNK_SIZE]),
            &vec![2u8; CHUNK_SIZE][..]
        );
        assert_eq!(
            roundtrip(&vec![3u8; CHUNK_SIZE + 7]),
            &vec![3u8; CHUNK_SIZE + 7][..]
        );
    }

    #[test]
    fn truncation_detected() {
        let mut enc: Vec<u8> = Vec::new();
        let mut r = b"hello world".as_slice();
        encrypt_stream(&mut r, &mut enc, &dek(), "01SNAP", "abcd").unwrap();
        enc.truncate(enc.len() - 1); // drop last byte of sentinel tag
        let mut out: Vec<u8> = Vec::new();
        let mut reader = enc.as_slice();
        let err = decrypt_stream(&mut reader, &mut out, &dek(), "01SNAP", "abcd").unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    fn wrong_snapshot_id_rejected() {
        let mut enc: Vec<u8> = Vec::new();
        let mut r = b"data".as_slice();
        encrypt_stream(&mut r, &mut enc, &dek(), "01SNAP", "abcd").unwrap();
        let mut out: Vec<u8> = Vec::new();
        let mut reader = enc.as_slice();
        let err = decrypt_stream(&mut reader, &mut out, &dek(), "OTHER", "abcd").unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    fn bad_magic_rejected() {
        let mut enc: Vec<u8> = vec![0u8; 8];
        enc.extend_from_slice(&[0u8; 4]);
        let mut out: Vec<u8> = Vec::new();
        let mut reader = enc.as_slice();
        let err = decrypt_stream(&mut reader, &mut out, &dek(), "01SNAP", "abcd").unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    fn truncation_to_empty_detected() {
        // Encrypt a multi-chunk plaintext, then move the genuine trailing
        // sentinel to the front of a truncated container (magic + chunk_size +
        // sentinel). The sentinel was encrypted with AD index = N (the data
        // chunk count), but at the front expected_index = 0, so GCM auth fails.
        let mut enc: Vec<u8> = Vec::new();
        let mut r = b"hello world".as_slice();
        encrypt_stream(&mut r, &mut enc, &dek(), "01SNAP", "abcd").unwrap();
        assert!(enc.len() > 12 + FILE_MAGIC.len() + 4);
        // Header = magic(8) + chunk_size(4). Trailing sentinel record =
        // nonce(12) + len_be_u32(0) + tag(16).
        let header_len = FILE_MAGIC.len() + 4;
        let sentinel_len = 12 + 4 + 16;
        let sentinel = enc[enc.len() - sentinel_len..].to_vec();
        let mut trunc: Vec<u8> = Vec::with_capacity(header_len + sentinel_len);
        trunc.extend_from_slice(&enc[..header_len]);
        trunc.extend_from_slice(&sentinel);
        let mut out: Vec<u8> = Vec::new();
        let mut reader = trunc.as_slice();
        let err = decrypt_stream(&mut reader, &mut out, &dek(), "01SNAP", "abcd").unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn oversized_chunk_len_rejected_before_alloc() {
        // Craft a container whose first data record claims len = u32::MAX.
        // Must return CiphertextCorrupt WITHOUT a ~4 GiB allocation.
        let mut enc: Vec<u8> = Vec::new();
        enc.extend_from_slice(FILE_MAGIC);
        enc.extend_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
        // first record: a nonce + bogus oversized length, no body needed
        enc.extend_from_slice(&[0u8; 12]);
        enc.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut out: Vec<u8> = Vec::new();
        let mut reader = enc.as_slice();
        let err = decrypt_stream(&mut reader, &mut out, &dek(), "01SNAP", "abcd").unwrap_err();
        assert!(matches!(err, SealError::CiphertextCorrupt), "{err:?}");
    }
}
