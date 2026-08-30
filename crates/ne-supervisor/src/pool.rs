// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Warm pool for one tier: pre-forked, identity-reset, not-yet-registered instances.
//!
//! Pre-forked [`firecracker::Instance`]s are held ready so `create(tier)` is a
//! near-zero-latency handout instead of a cold boot. Members are produced by the
//! supervisor's `boot_ready_reset` fork sequence; this module owns
//! only the pool state and refill arithmetic. The `WorkspaceManager` drives
//! provisioning.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;

use crate::firecracker::Instance;

/// How often the refill loop re-evaluates the pool deficit absent a kick.
pub(crate) const POOL_REFILL_INTERVAL: Duration = Duration::from_millis(500);

/// Operator-supplied warm-pool configuration. Single tier in v1.
#[derive(Debug, Clone)]
pub struct WarmPoolConfig {
    /// Logical tier name a `create(tier=…)` must match.
    pub tier_name: String,
    /// Base snapshot every member is forked from.
    pub base_snapshot_id: String,
    /// Target number of ready members.
    pub target_size: usize,
    /// Cap on concurrent in-flight provisions during refill.
    pub max_in_flight: usize,
}

/// The warm pool: immutable config + ready members + an in-flight counter.
#[derive(Debug)]
pub struct WarmPool {
    cfg: WarmPoolConfig,
    /// Ready members. Kept separate from `in_flight` so a [`ProvisionPermit`]
    /// can release its slot from `Drop` (which is synchronous) without needing
    /// to take this async lock.
    members: Mutex<VecDeque<Instance>>,
    /// Count of provisions currently booting. Each is owned by a
    /// [`ProvisionPermit`] that releases it on success (via
    /// [`WarmPool::complete_provision`]) or on drop — including when the
    /// provisioning task panics — so an in-flight slot can never leak and
    /// permanently shrink the effective target size.
    in_flight: AtomicUsize,
}

impl WarmPool {
    /// Create a new warm pool with the given operator configuration.
    #[must_use]
    pub fn new(cfg: WarmPoolConfig) -> Self {
        Self {
            cfg,
            members: Mutex::new(VecDeque::new()),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Return the operator configuration this pool was created with.
    #[must_use]
    pub fn config(&self) -> &WarmPoolConfig {
        &self.cfg
    }

    /// Reserve up to `refill_deficit(...)` provision slots, returning one RAII
    /// [`ProvisionPermit`] per slot. Each permit holds its `in_flight`
    /// reservation and releases it on drop, so even a panicking provision task
    /// cannot leak the slot. The capacity check and the reservation both happen
    /// under the members lock so concurrent refill ticks cannot over-reserve.
    pub async fn reserve_provisions(self: &Arc<Self>) -> Vec<ProvisionPermit> {
        let members = self.members.lock().await;
        let n = refill_deficit(
            self.cfg.target_size,
            members.len(),
            self.in_flight.load(Ordering::Acquire),
            self.cfg.max_in_flight,
        );
        self.in_flight.fetch_add(n, Ordering::AcqRel);
        drop(members);
        (0..n)
            .map(|_| ProvisionPermit {
                pool: Arc::clone(self),
                released: false,
            })
            .collect()
    }

    /// A provision finished successfully: stow the member and consume its
    /// permit, moving the slot from in-flight to available.
    pub async fn complete_provision(&self, member: Instance, mut permit: ProvisionPermit) {
        self.members.lock().await.push_back(member);
        permit.release();
    }

    /// Pop one ready member, if any.
    pub async fn pop(&self) -> Option<Instance> {
        self.members.lock().await.pop_front()
    }

    /// Drain every member for shutdown reaping.
    pub async fn drain(&self) -> Vec<Instance> {
        self.members.lock().await.drain(..).collect()
    }

    /// Counts for status reporting: (available, `in_flight`).
    pub async fn counts(&self) -> (usize, usize) {
        let available = self.members.lock().await.len();
        (available, self.in_flight.load(Ordering::Acquire))
    }
}

/// RAII reservation for one in-flight provision slot.
///
/// The success path passes the permit to [`WarmPool::complete_provision`], which
/// releases it as the member is stowed. Every other path — an expected
/// provision error, or a panic in the provision task — drops the permit, and
/// `Drop` releases the slot. Release is idempotent, so the success path's
/// explicit release plus the end-of-scope drop never double-count.
#[derive(Debug)]
pub struct ProvisionPermit {
    pool: Arc<WarmPool>,
    released: bool,
}

impl ProvisionPermit {
    /// Release the reserved slot exactly once.
    fn release(&mut self) {
        if !self.released {
            self.pool.in_flight.fetch_sub(1, Ordering::AcqRel);
            self.released = true;
        }
    }
}

impl Drop for ProvisionPermit {
    fn drop(&mut self) {
        self.release();
    }
}

/// How many new provisions to start: enough to reach `target` accounting for
/// what's already available and in flight, capped by remaining `max_in_flight`.
#[must_use]
pub(crate) fn refill_deficit(
    target: usize,
    available: usize,
    in_flight: usize,
    max_in_flight: usize,
) -> usize {
    let want = target.saturating_sub(available + in_flight);
    let cap = max_in_flight.saturating_sub(in_flight);
    want.min(cap)
}

#[cfg(test)]
mod tests {
    use super::refill_deficit;

    #[test]
    fn empty_pool_reserves_up_to_max_in_flight() {
        assert_eq!(refill_deficit(4, 0, 0, 2), 2);
    }

    #[test]
    fn counts_available_and_in_flight_against_target() {
        assert_eq!(refill_deficit(4, 1, 1, 2), 1);
    }

    #[test]
    fn full_pool_reserves_nothing() {
        assert_eq!(refill_deficit(4, 4, 0, 2), 0);
        assert_eq!(refill_deficit(4, 2, 2, 2), 0);
    }

    #[test]
    fn never_underflows() {
        assert_eq!(refill_deficit(2, 5, 0, 2), 0);
        assert_eq!(refill_deficit(2, 0, 5, 2), 0);
    }
}
