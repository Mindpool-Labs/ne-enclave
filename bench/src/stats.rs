// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Percentile + summary statistics over per-trial latency samples.
//!
//! Percentiles use the nearest-rank method: for percentile p over n sorted
//! samples, rank = ceil(p/100 * n), 1-based, clamped to [1, n].

/// Summary statistics for one benchmark's latency samples, in milliseconds.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// Number of samples.
    pub n: usize,
    /// Minimum latency in milliseconds.
    pub min_ms: f64,
    /// Maximum latency in milliseconds.
    pub max_ms: f64,
    /// Arithmetic mean latency in milliseconds.
    pub mean_ms: f64,
    /// Population standard deviation of latency in milliseconds.
    pub stddev_ms: f64,
    /// 50th-percentile (median) latency in milliseconds.
    pub p50_ms: f64,
    /// 90th-percentile latency in milliseconds.
    pub p90_ms: f64,
    /// 95th-percentile latency in milliseconds.
    pub p95_ms: f64,
    /// 99th-percentile latency in milliseconds.
    pub p99_ms: f64,
}

/// Nearest-rank percentile of `samples` (need not be pre-sorted).
/// Returns `None` for an empty slice. `p` is clamped to [0.0, 100.0].
#[must_use]
// cast_precision_loss: n is a sample count (bench runs ≤ millions), fits f64 exactly.
// cast_possible_truncation / cast_sign_loss: rank = ceil(…) of a non-negative f64 ≤ n;
// the saturating_sub+min clamp keeps it in [0, n-1] so no truncation risk.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn percentile(samples: &[f64], p: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p = p.clamp(0.0, 100.0);
    let n = sorted.len();
    // nearest-rank, 1-based
    let rank = (p / 100.0 * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    Some(sorted[idx])
}

/// Compute a [`Summary`]; returns `None` for an empty slice.
#[must_use]
// cast_precision_loss: n is a sample count (bench runs ≤ millions), fits f64 exactly.
#[allow(clippy::cast_precision_loss)]
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len();
    let sum: f64 = samples.iter().sum();
    let mean = sum / n as f64;
    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let min = samples.iter().copied().fold(f64::INFINITY, f64::min);
    let max = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Some(Summary {
        n,
        min_ms: min,
        max_ms: max,
        mean_ms: mean,
        stddev_ms: variance.sqrt(),
        p50_ms: percentile(samples, 50.0)?,
        p90_ms: percentile(samples, 90.0)?,
        p95_ms: percentile(samples, 95.0)?,
        p99_ms: percentile(samples, 99.0)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_empty_is_none() {
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn percentile_nearest_rank_known_values() {
        // 1..=10. nearest-rank: p50 -> rank ceil(0.5*10)=5 -> value 5.
        let xs: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(percentile(&xs, 50.0), Some(5.0));
        // p90 -> rank 9 -> 9; p95 -> rank ceil(9.5)=10 -> 10; p99 -> 10.
        assert_eq!(percentile(&xs, 90.0), Some(9.0));
        assert_eq!(percentile(&xs, 95.0), Some(10.0));
        assert_eq!(percentile(&xs, 99.0), Some(10.0));
        // The zero percentile clamps to rank 1; the hundredth percentile clamps to rank 10.
        assert_eq!(percentile(&xs, 0.0), Some(1.0));
        assert_eq!(percentile(&xs, 100.0), Some(10.0));
    }

    #[test]
    fn percentile_unsorted_input() {
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 50.0), Some(2.0));
    }

    #[test]
    // float_cmp: values are assigned from integer literals with no arithmetic;
    // exact bit-equality is the correct assertion here.
    #[allow(clippy::float_cmp)]
    fn summarize_single_value() {
        let s = summarize(&[42.0]).unwrap();
        assert_eq!(s.n, 1);
        assert_eq!(s.min_ms, 42.0);
        assert_eq!(s.max_ms, 42.0);
        assert_eq!(s.mean_ms, 42.0);
        assert_eq!(s.stddev_ms, 0.0);
        assert_eq!(s.p50_ms, 42.0);
    }

    #[test]
    fn summarize_known_mean_and_stddev() {
        // [2,4,4,4,5,5,7,9] mean 5, population stddev 2.
        let xs = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let s = summarize(&xs).unwrap();
        assert_eq!(s.n, 8);
        assert!((s.mean_ms - 5.0).abs() < 1e-9);
        assert!((s.stddev_ms - 2.0).abs() < 1e-9);
        // min/max are taken directly from the input; exact equality holds.
        #[allow(clippy::float_cmp)] // min/max are identity operations on input literals
        {
            assert_eq!(s.min_ms, 2.0);
            assert_eq!(s.max_ms, 9.0);
        }
    }

    #[test]
    fn summarize_empty_is_none() {
        assert!(summarize(&[]).is_none());
    }
}
