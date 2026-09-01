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

use crate::capacity::{
    CapacityError, CapacityLedger, PoolCapacityReservation, ReadyPoolCapacityGuard,
    capacity_dimensions,
};
use crate::firecracker::Instance;
use crate::workspace::LifecycleTasks;

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
    lifecycle_tasks: Arc<LifecycleTasks>,
    /// Ready members. Kept separate from `in_flight` so a [`ProvisionPermit`]
    /// can release its slot from `Drop` (which is synchronous) without needing
    /// to take this async lock.
    members: Mutex<VecDeque<PoolMember>>,
    /// Count of provisions currently booting. Each is owned by a
    /// [`ProvisionPermit`] that releases it on success (via
    /// [`WarmPool::complete_provision`]) or on drop — including when the
    /// provisioning task panics — so an in-flight slot can never leak and
    /// permanently shrink the effective target size.
    in_flight: AtomicUsize,
    #[cfg(test)]
    push_waiting: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

impl WarmPool {
    /// Create a new warm pool with the given operator configuration.
    #[must_use]
    pub fn new(cfg: WarmPoolConfig) -> Self {
        Self::with_lifecycle(cfg, Arc::new(LifecycleTasks::new()))
    }

    /// Create a pool whose members use the supervisor lifecycle tracker.
    #[must_use]
    pub(crate) fn with_lifecycle(
        cfg: WarmPoolConfig,
        lifecycle_tasks: Arc<LifecycleTasks>,
    ) -> Self {
        Self {
            cfg,
            lifecycle_tasks,
            members: Mutex::new(VecDeque::new()),
            in_flight: AtomicUsize::new(0),
            #[cfg(test)]
            push_waiting: Mutex::new(None),
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
    pub(crate) async fn reserve_provisions(
        self: &Arc<Self>,
        ledger: &CapacityLedger,
        cpu_millicores: u64,
        memory_bytes: u64,
    ) -> Result<Vec<ProvisionPermit>, CapacityError> {
        let members = self.members.lock().await;
        let n = refill_deficit(
            self.cfg.target_size,
            members.len(),
            self.in_flight.load(Ordering::Acquire),
            self.cfg.max_in_flight,
        );
        let reservations = ledger.reserve_pool_batch(n, cpu_millicores, memory_bytes)?;
        let mut permits = Vec::with_capacity(reservations.len());
        for capacity in reservations {
            self.in_flight.fetch_add(1, Ordering::AcqRel);
            permits.push(ProvisionPermit {
                pool: Arc::clone(self),
                capacity: Some(capacity),
                cpu_millicores,
                memory_bytes,
                released: false,
            });
        }
        drop(members);
        Ok(permits)
    }

    /// A provision finished successfully: stow the member and consume its
    /// permit, moving the slot from in-flight to available.
    pub(crate) async fn complete_provision(
        &self,
        member: Instance,
        mut permit: ProvisionPermit,
    ) -> Result<(), RejectedPoolProvision> {
        let (cpu_millicores, memory_bytes) =
            match capacity_dimensions(u64::from(member.vcpu_count), u64::from(member.mem_size_mib))
            {
                Ok(dimensions) => dimensions,
                Err(_) => {
                    return Err(RejectedPoolProvision::new(
                        member,
                        permit,
                        PoolCompletionError::DimensionMismatch,
                    ));
                }
            };
        if cpu_millicores != permit.cpu_millicores || memory_bytes != permit.memory_bytes {
            return Err(RejectedPoolProvision::new(
                member,
                permit,
                PoolCompletionError::DimensionMismatch,
            ));
        }
        let capacity = match permit.capacity.as_mut() {
            Some(capacity) => capacity,
            None => {
                return Err(RejectedPoolProvision::new(
                    member,
                    permit,
                    PoolCompletionError::MissingPermit,
                ));
            }
        };
        let guard = match capacity.ready_in_place() {
            Ok(guard) => guard,
            Err(error) => {
                return Err(RejectedPoolProvision::new(
                    member,
                    permit,
                    PoolCompletionError::Capacity(error),
                ));
            }
        };
        let _ = permit.capacity.take();
        let member = PoolMember::new(member, guard, Arc::clone(&self.lifecycle_tasks));
        #[cfg(test)]
        if let Some(waiting) = self.push_waiting.lock().await.clone() {
            waiting.notify_one();
        }
        self.members.lock().await.push_back(member);
        permit.release();
        Ok(())
    }

    /// Pop one ready member, if any.
    pub(crate) async fn pop(&self) -> Option<PoolMember> {
        self.members.lock().await.pop_front()
    }

    /// Drain every member for shutdown reaping.
    pub(crate) async fn drain(&self) -> Vec<PoolMember> {
        self.members.lock().await.drain(..).collect()
    }

    /// Counts for status reporting: (available, `in_flight`).
    pub async fn counts(&self) -> (usize, usize) {
        let available = self.members.lock().await.len();
        (available, self.in_flight.load(Ordering::Acquire))
    }

    #[cfg(test)]
    async fn set_push_waiting_hook(&self, hook: Arc<tokio::sync::Notify>) {
        *self.push_waiting.lock().await = Some(hook);
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
pub(crate) struct ProvisionPermit {
    pool: Arc<WarmPool>,
    capacity: Option<PoolCapacityReservation>,
    cpu_millicores: u64,
    memory_bytes: u64,
    released: bool,
}

/// A rejected provision retains the launched instance and the in-flight
/// reservation until process exit is confirmed.
#[derive(Debug)]
pub(crate) struct RejectedPoolProvision {
    instance: Option<Instance>,
    permit: Option<ProvisionPermit>,
    error: PoolCompletionError,
}

/// A ready instance and the capacity entry it owns until registry adoption.
#[derive(Debug)]
pub(crate) struct PoolMember {
    instance: Option<Instance>,
    capacity_guard: Option<ReadyPoolCapacityGuard>,
    lifecycle_tasks: Arc<LifecycleTasks>,
}

impl PoolMember {
    fn new(
        instance: Instance,
        capacity_guard: ReadyPoolCapacityGuard,
        lifecycle_tasks: Arc<LifecycleTasks>,
    ) -> Self {
        Self {
            instance: Some(instance),
            capacity_guard: Some(capacity_guard),
            lifecycle_tasks,
        }
    }

    pub(crate) fn instance(&self) -> Option<&Instance> {
        self.instance.as_ref()
    }

    pub(crate) fn instance_mut(&mut self) -> Option<&mut Instance> {
        self.instance.as_mut()
    }

    pub(crate) fn take_parts(&mut self) -> Option<(Instance, ReadyPoolCapacityGuard)> {
        Some((self.instance.take()?, self.capacity_guard.take()?))
    }

    pub(crate) async fn teardown(mut self) {
        let Some(instance) = self.instance.take() else {
            return;
        };
        let Some(guard) = self.capacity_guard.take() else {
            return;
        };
        match crate::firecracker::terminate(instance, Duration::from_secs(5)).await {
            Ok(()) => drop(guard),
            Err(error) => {
                guard.fail_closed();
                std::mem::forget((error, guard));
            }
        }
    }
}

impl Drop for PoolMember {
    fn drop(&mut self) {
        let Some(instance) = self.instance.take() else {
            return;
        };
        let Some(guard) = self.capacity_guard.take() else {
            return;
        };
        let lifecycle_tasks = Arc::clone(&self.lifecycle_tasks);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            match lifecycle_tasks.begin_cleanup() {
                Ok(permit) => LifecycleTasks::spawn_started_cleanup(permit, handle, async move {
                    match crate::firecracker::terminate(instance, Duration::from_secs(5)).await {
                        Ok(()) => drop(guard),
                        Err(error) => {
                            guard.fail_closed();
                            std::mem::forget((error, guard));
                        }
                    }
                }),
                Err(_) => std::mem::forget((instance, guard)),
            }
        } else {
            let Ok(permit) = lifecycle_tasks.begin_cleanup() else {
                std::mem::forget((instance, guard));
                return;
            };
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(async move {
                    let _permit = permit;
                    match crate::firecracker::terminate(instance, Duration::from_secs(5)).await {
                        Ok(()) => drop(guard),
                        Err(error) => {
                            guard.fail_closed();
                            std::mem::forget((error, guard));
                        }
                    }
                }),
                Err(_) => std::mem::forget((instance, guard, permit)),
            }
        }
    }
}

/// A ready member could not be placed in the pool.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PoolCompletionError {
    #[error("pool provision dimensions differ from signed reservation")]
    DimensionMismatch,
    #[error("pool provision capacity permit is missing")]
    MissingPermit,
    #[error("pool capacity transition failed: {0}")]
    Capacity(#[source] CapacityError),
}

impl ProvisionPermit {
    /// Release the reserved slot exactly once.
    fn release(&mut self) {
        if !self.released {
            self.pool.in_flight.fetch_sub(1, Ordering::AcqRel);
            self.released = true;
        }
    }

    fn fail_closed(&self) {
        if let Some(capacity) = &self.capacity {
            capacity.fail_closed();
        }
    }
}

impl Drop for ProvisionPermit {
    fn drop(&mut self) {
        self.release();
    }
}

impl RejectedPoolProvision {
    fn new(instance: Instance, permit: ProvisionPermit, error: PoolCompletionError) -> Self {
        Self {
            instance: Some(instance),
            permit: Some(permit),
            error,
        }
    }

    pub(crate) fn error(&self) -> &PoolCompletionError {
        &self.error
    }

    /// Release the permit only after the rejected child has been reaped.
    pub(crate) async fn teardown(mut self) {
        let (Some(instance), Some(permit)) = (self.instance.take(), self.permit.take()) else {
            return;
        };
        match crate::firecracker::terminate(instance, Duration::from_secs(5)).await {
            Ok(()) => drop(permit),
            Err(error) => {
                permit.fail_closed();
                std::mem::forget((error, permit));
            }
        }
    }
}

impl Drop for RejectedPoolProvision {
    fn drop(&mut self) {
        let (Some(instance), Some(permit)) = (self.instance.take(), self.permit.take()) else {
            return;
        };
        let tasks = Arc::clone(&permit.pool.lifecycle_tasks);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            match tasks.begin_cleanup() {
                Ok(cleanup) => LifecycleTasks::spawn_started_cleanup(cleanup, handle, async move {
                    match crate::firecracker::terminate(instance, Duration::from_secs(5)).await {
                        Ok(()) => drop(permit),
                        Err(error) => {
                            permit.fail_closed();
                            std::mem::forget((error, permit));
                        }
                    }
                }),
                Err(_) => std::mem::forget((instance, permit)),
            }
        } else {
            permit.fail_closed();
            std::mem::forget((instance, permit));
        }
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
    use super::{PoolCompletionError, WarmPool, WarmPoolConfig, refill_deficit};
    use crate::capacity::CapacityLedger;
    use crate::firecracker::Instance;
    use ne_protocol::profile::ExecutionProfile;
    use std::sync::Arc;
    use std::time::Duration;

    async fn long_running_instance(temp: &tempfile::TempDir, id: &str) -> (Instance, u32) {
        let jailer_root = temp.path().join("jailer");
        std::fs::create_dir_all(jailer_root.join("root")).expect("test chroot");
        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep child");
        let pid = child.id().expect("child pid");
        (
            Instance {
                workspace_id: id.to_string(),
                boot_id: "boot".to_string(),
                child,
                firecracker_pid: pid,
                api_socket_host: temp.path().join("api"),
                vsock_host_socket: temp.path().join("vsock"),
                jailer_chroot: jailer_root.join("root"),
                jailer_uid: 0,
                jailer_gid: 0,
                lifecycle_state: ne_protocol::supervisor::WorkspaceState::Running,
                network_slot: None,
                guest_vsock_cid: 3,
                vcpu_count: 1,
                mem_size_mib: 1,
                kernel_boot_args: String::new(),
                kernel_sha256: "11".repeat(32),
                rootfs_sha256: "22".repeat(32),
                rootfs_read_only: true,
            },
            pid,
        )
    }

    async fn wait_for_pool_cleanup(
        pool: &WarmPool,
        ledger: &CapacityLedger,
        jailer_root: &std::path::Path,
        pid: u32,
    ) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let exited = matches!(
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(i32::try_from(pid).expect("pid")),
                        None
                    ),
                    Err(nix::errno::Errno::ESRCH)
                );
                let released = ledger
                    .snapshot(ExecutionProfile::Standard)
                    .map(|snapshot| snapshot.warm_pool_reserved_slots == 0)
                    .unwrap_or(false);
                if exited && !jailer_root.exists() && released && pool.counts().await.1 == 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled pool owner must reap child, remove chroot, and release capacity");
    }

    fn pool() -> Arc<WarmPool> {
        Arc::new(WarmPool::new(WarmPoolConfig {
            tier_name: "test".to_string(),
            base_snapshot_id: "snap".to_string(),
            target_size: 2,
            max_in_flight: 2,
        }))
    }

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

    #[tokio::test]
    async fn reservation_at_ledger_ceiling_creates_no_pool_entry_or_in_flight_slot() {
        let ledger = CapacityLedger::new(1);
        let _workspace = ledger
            .reserve_workspace("busy", 1_000, 1)
            .expect("workspace");
        let pool = pool();
        let permits = pool
            .reserve_provisions(&ledger, 1_000, 1)
            .await
            .expect("full tick is deferred without an accounting error");
        assert!(permits.is_empty());
        assert_eq!(pool.counts().await, (0, 0));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("snapshot")
                .warm_pool_reserved_slots,
            0
        );
    }

    #[tokio::test]
    async fn dropping_a_provision_permit_releases_pool_and_ledger_capacity() {
        let ledger = CapacityLedger::new(2);
        let pool = pool();
        let permits = pool
            .reserve_provisions(&ledger, 1_000, 1)
            .await
            .expect("permits");
        assert_eq!(permits.len(), 2);
        assert_eq!(pool.counts().await, (0, 2));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("snapshot")
                .warm_pool_reserved_slots,
            2
        );
        drop(permits);
        assert_eq!(pool.counts().await, (0, 0));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("snapshot")
                .warm_pool_reserved_slots,
            0
        );
    }

    #[tokio::test]
    async fn concurrent_reservations_do_not_exceed_target_or_in_flight_limit() {
        let ledger = Arc::new(CapacityLedger::new(8));
        let pool = pool();
        let left_pool = Arc::clone(&pool);
        let left_ledger = Arc::clone(&ledger);
        let left = tokio::spawn(async move {
            left_pool
                .reserve_provisions(&left_ledger, 1_000, 1)
                .await
                .expect("left")
        });
        let right_pool = Arc::clone(&pool);
        let right_ledger = Arc::clone(&ledger);
        let right = tokio::spawn(async move {
            right_pool
                .reserve_provisions(&right_ledger, 1_000, 1)
                .await
                .expect("right")
        });
        let left = left.await.expect("left task");
        let right = right.await.expect("right task");
        assert!(left.len() + right.len() <= 2);
        assert_eq!(pool.counts().await, (0, left.len() + right.len()));
    }

    #[tokio::test]
    async fn completion_dimension_mismatch_keeps_pool_capacity_until_child_cleanup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let jailer_root = temp.path().join("jailer").join("pool-test");
        let jailer_chroot = jailer_root.join("root");
        tokio::fs::create_dir_all(&jailer_chroot)
            .await
            .expect("test chroot");
        let ledger = CapacityLedger::new(2);
        let pool = pool();
        let permit = pool
            .reserve_provisions(&ledger, 1_000, 1)
            .await
            .expect("permit")
            .pop()
            .expect("one permit");
        let child = tokio::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("child");
        let firecracker_pid = child.id().expect("child pid");
        let instance = Instance {
            workspace_id: "pool-test".to_string(),
            boot_id: "boot".to_string(),
            child,
            firecracker_pid,
            api_socket_host: jailer_root.join("api.sock"),
            vsock_host_socket: jailer_root.join("vsock.sock"),
            jailer_chroot,
            jailer_uid: 0,
            jailer_gid: 0,
            lifecycle_state: ne_protocol::supervisor::WorkspaceState::Running,
            network_slot: None,
            guest_vsock_cid: 3,
            vcpu_count: 2,
            mem_size_mib: 1,
            kernel_boot_args: String::new(),
            kernel_sha256: "11".repeat(32),
            rootfs_sha256: "22".repeat(32),
            rootfs_read_only: true,
        };
        let rejected = pool
            .complete_provision(instance, permit)
            .await
            .expect_err("mismatch");
        assert!(matches!(
            rejected.error(),
            PoolCompletionError::DimensionMismatch
        ));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("live rejected child remains accounted")
                .warm_pool_reserved_slots,
            1,
            "rejecting a live child must not release its provision reservation"
        );
        rejected.teardown().await;
        assert_eq!(pool.counts().await, (0, 0));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("snapshot")
                .warm_pool_reserved_slots,
            0
        );
    }

    // Break caught: a child-control failure during rejected-provision cleanup
    // used to drop the permit and publish its pool slot while exit was unknown.
    #[tokio::test]
    async fn rejected_provision_faults_instead_of_releasing_capacity_on_termination_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let jailer_root = temp.path().join("jailer").join("rejected-failure");
        let jailer_chroot = jailer_root.join("root");
        tokio::fs::create_dir_all(&jailer_chroot)
            .await
            .expect("test chroot");
        let ledger = CapacityLedger::new(1);
        let pool = Arc::new(WarmPool::new(WarmPoolConfig {
            tier_name: "test".to_string(),
            base_snapshot_id: "snap".to_string(),
            target_size: 1,
            max_in_flight: 1,
        }));
        let permit = pool
            .reserve_provisions(&ledger, 1_000, 1_024 * 1_024)
            .await
            .expect("permit")
            .pop()
            .expect("one permit");
        let child = tokio::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("child");
        let firecracker_pid = child.id().expect("child pid");
        let rejected = pool
            .complete_provision(
                Instance {
                    workspace_id: "rejected-failure".to_string(),
                    boot_id: "boot".to_string(),
                    child,
                    firecracker_pid,
                    api_socket_host: jailer_root.join("api.sock"),
                    vsock_host_socket: jailer_root.join("vsock.sock"),
                    jailer_chroot,
                    jailer_uid: 0,
                    jailer_gid: 0,
                    lifecycle_state: ne_protocol::supervisor::WorkspaceState::Running,
                    network_slot: None,
                    guest_vsock_cid: 3,
                    vcpu_count: 2,
                    mem_size_mib: 1,
                    kernel_boot_args: String::new(),
                    kernel_sha256: "11".repeat(32),
                    rootfs_sha256: "22".repeat(32),
                    rootfs_read_only: true,
                },
                permit,
            )
            .await
            .expect_err("dimension mismatch");
        crate::firecracker::inject_child_control_failure_once_for_test("rejected-failure", "boot");
        rejected.teardown().await;
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(crate::capacity::CapacityError::Faulted)
        ));
    }

    #[tokio::test]
    async fn cancellation_before_pool_push_reaps_member_before_capacity_release() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ledger = Arc::new(CapacityLedger::new(1));
        let pool = pool();
        let permit = pool
            .reserve_provisions(&ledger, 1_000, 1_024 * 1_024)
            .await
            .expect("permit")
            .pop()
            .expect("one permit");
        let (instance, pid) = long_running_instance(&temp, "push-cancel").await;
        let waiting = Arc::new(tokio::sync::Notify::new());
        pool.set_push_waiting_hook(Arc::clone(&waiting)).await;
        let queue_lock = pool.members.lock().await;
        let task_pool = Arc::clone(&pool);
        let task =
            tokio::spawn(async move { task_pool.complete_provision(instance, permit).await });
        tokio::time::timeout(Duration::from_secs(1), waiting.notified())
            .await
            .expect("owner constructed before queue wait");
        task.abort();
        let _ = task.await;
        drop(queue_lock);
        wait_for_pool_cleanup(&pool, &ledger, &temp.path().join("jailer"), pid).await;
    }

    #[tokio::test]
    async fn cancellation_after_pool_pop_reaps_member_before_capacity_release() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ledger = Arc::new(CapacityLedger::new(1));
        let pool = pool();
        let permit = pool
            .reserve_provisions(&ledger, 1_000, 1_024 * 1_024)
            .await
            .expect("permit")
            .pop()
            .expect("one permit");
        let (instance, pid) = long_running_instance(&temp, "pop-cancel").await;
        pool.complete_provision(instance, permit)
            .await
            .expect("ready member");
        let member = pool.pop().await.expect("checked-out member");
        let (_release_probe, probe_wait) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _member = member;
            let _ = probe_wait.await;
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        wait_for_pool_cleanup(&pool, &ledger, &temp.path().join("jailer"), pid).await;
    }
}
