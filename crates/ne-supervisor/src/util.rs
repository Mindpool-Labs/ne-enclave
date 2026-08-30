// SPDX-FileCopyrightText: 2026 Mindpool, Inc. <dev@mindpool.io>
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Small shared supervisor utilities.

use std::io::{self, ErrorKind};
use std::sync::LazyLock;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// Read one newline-delimited frame, rejecting anything larger than `max`
/// bytes instead of growing the buffer without bound (memory-exhaustion `DoS`).
/// Reads at most `max + 1` bytes: if the newline has not arrived by then the
/// frame is over the cap and is rejected.
pub(crate) async fn read_capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    max: u64,
) -> io::Result<usize> {
    let mut limited = reader.take(max + 1);
    let n = limited.read_line(buf).await?;
    if n as u64 > max {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "frame exceeds maximum size",
        ));
    }
    Ok(n)
}

/// Parse an optional string env override into a positive integer, rejecting a
/// zero, negative, or unparseable value by falling back to `default`. Shared by
/// the byte-cap knobs (`NE_MAX_GUEST_FRAME_BYTES` u64, `NE_MAX_EXEC_OUTPUT_BYTES`
/// usize) so a literal `0` cannot silently install a fail-closed cap that bricks
/// vsock RPC / discards all exec output — parity with the timeout knobs
/// ([`parse_ceiling`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_positive_or<T>(raw: Option<String>, default: T) -> T
where
    T: std::str::FromStr + PartialOrd + Default,
{
    raw.and_then(|v| v.parse::<T>().ok())
        .filter(|v| *v > T::default())
        .unwrap_or(default)
}

/// Clamp a client-supplied `timeout_ms` so 0 ("no bound") or an
/// over-ceiling value resolves to `ceiling`. Guarantees a wall-clock deadline.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn clamp_timeout_ms(requested: u32, ceiling: u32) -> u32 {
    if requested == 0 || requested > ceiling {
        ceiling
    } else {
        requested
    }
}

/// Parse the `NE_MAX_EXEC_TIMEOUT_MS` override. A missing, unparseable, or
/// zero value falls back to the 1-hour default — 0 is rejected because a zero
/// ceiling would make `clamp_timeout_ms` return 0 for every input, and the
/// call sites treat 0 as "no bound" (reopening the unbounded-wait hole).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_ceiling(raw: Option<String>) -> u32 {
    raw.and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(3_600_000)
}

/// Ceiling that any client `timeout_ms` is clamped to. Default 1 hour.
/// The env override rejects 0 (falls back to the default) — see
/// [`parse_ceiling`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) static MAX_EXEC_TIMEOUT_MS: LazyLock<u32> =
    LazyLock::new(|| parse_ceiling(std::env::var("NE_MAX_EXEC_TIMEOUT_MS").ok()));

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let data = [b'x'; 64];
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let err = read_capped_line(&mut reader, &mut line, 16)
            .await
            .expect_err("oversized frame must error");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn accepts_frame_at_cap() {
        let data = b"hello\n";
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let n = read_capped_line(&mut reader, &mut line, 16).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(line, "hello\n");
    }

    #[test]
    fn clamp_timeout_zero_becomes_ceiling() {
        assert_eq!(clamp_timeout_ms(0, 3_600_000), 3_600_000);
    }
    #[test]
    fn clamp_timeout_over_ceiling_becomes_ceiling() {
        assert_eq!(clamp_timeout_ms(9_000_000, 3_600_000), 3_600_000);
    }
    #[test]
    fn clamp_timeout_in_range_unchanged() {
        assert_eq!(clamp_timeout_ms(5_000, 3_600_000), 5_000);
    }
    #[test]
    fn clamp_timeout_at_ceiling_passes_through() {
        assert_eq!(clamp_timeout_ms(3_600_000, 3_600_000), 3_600_000);
    }

    // MAX_EXEC_TIMEOUT_MS itself is env-dependent + process-global (LazyLock),
    // so its parsing is tested via the pure `parse_ceiling` helper instead of
    // racy `std::env::set_var` manipulation.
    #[test]
    fn parse_ceiling_rejects_zero_and_garbage() {
        assert_eq!(parse_ceiling(None), 3_600_000);
        assert_eq!(parse_ceiling(Some("0".into())), 3_600_000);
        assert_eq!(parse_ceiling(Some("not-a-number".into())), 3_600_000);
        assert_eq!(parse_ceiling(Some("120000".into())), 120_000);
    }

    // `parse_positive_or` backs the byte-cap knobs (u64 frame cap, usize exec
    // output cap); a 0/garbage override must fall back to the default (a 0-byte
    // cap is fail-closed but a silent footgun), and a valid value passes through.
    #[test]
    fn parse_positive_or_rejects_zero_and_garbage_u64() {
        assert_eq!(parse_positive_or(None, 100_u64), 100);
        assert_eq!(parse_positive_or(Some("0".into()), 100_u64), 100);
        assert_eq!(parse_positive_or(Some("garbage".into()), 100_u64), 100);
        assert_eq!(parse_positive_or(Some("512".into()), 100_u64), 512);
        // A valid positive override BELOW the default must be honored, not
        // clobbered — pins that the filter is `> 0`, not `> default`.
        assert_eq!(parse_positive_or(Some("50".into()), 100_u64), 50);
    }

    #[test]
    fn parse_positive_or_rejects_zero_and_garbage_usize() {
        assert_eq!(parse_positive_or(None, 4096_usize), 4096);
        assert_eq!(parse_positive_or(Some("0".into()), 4096_usize), 4096);
        assert_eq!(parse_positive_or(Some("bad".into()), 4096_usize), 4096);
        assert_eq!(parse_positive_or(Some("8192".into()), 4096_usize), 8192);
    }
}
