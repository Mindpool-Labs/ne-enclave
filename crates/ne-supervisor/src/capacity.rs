// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned atomic capacity accounting.
//!
//! ```text
//! workspace reserve -> registered guard owned by WorkspaceExec -> state change -> drop
//! pool reserve       -> ready guard owned by pool member -------> transfer to WorkspaceExec
//!        `------------> drop on failure/cancellation       `----> count-neutral adoption
//! ```
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![allow(clippy::redundant_pub_crate)] // private parent module keeps this crate-internal

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ne_protocol::fleet::RunnerCapacity;
use ne_protocol::profile::{ExecutionProfile, WorkspaceOperation};
use ne_protocol::supervisor::WorkspaceState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CapacityError {
    #[error("capacity ledger lock is poisoned")]
    Poisoned,
    #[error("workspace capacity is exhausted")]
    Exhausted,
    #[error("workspace capacity entry already exists")]
    DuplicateWorkspace,
    #[error("capacity entry is missing")]
    MissingEntry,
    #[error("capacity entry has an invalid state transition")]
    InvalidTransition,
    #[error("capacity accounting overflow")]
    ArithmeticOverflow,
    #[error("capacity ledger is faulted")]
    Faulted,
    #[error("capacity snapshot is invalid: {0}")]
    Snapshot(#[from] ne_protocol::fleet::FleetValidationError),
}

/// Convert signed workspace dimensions into public capacity units.
pub(crate) fn capacity_dimensions(
    vcpu_count: u64,
    mem_size_mib: u64,
) -> Result<(u64, u64), CapacityError> {
    let cpu_millicores = vcpu_count
        .checked_mul(1_000)
        .ok_or(CapacityError::ArithmeticOverflow)?;
    let memory_bytes = mem_size_mib
        .checked_mul(1_024 * 1_024)
        .ok_or(CapacityError::ArithmeticOverflow)?;
    Ok((cpu_millicores, memory_bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CapacityEntryId {
    Workspace(String),
    Pool(u64),
}

#[derive(Debug)]
struct CapacityState {
    revision: u64,
    faulted: bool,
    configured_workspace_ceiling: u32,
    next_pool_id: u64,
    workspaces: BTreeMap<CapacityEntryId, AccountedWorkspace>,
    pool_entries: BTreeMap<CapacityEntryId, AccountedPoolMember>,
}

#[derive(Debug)]
struct AccountedWorkspace {
    state: WorkspaceCapacityState,
    cpu_millicores: u64,
    memory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceCapacityState {
    Reserved,
    Registered(WorkspaceState),
}

#[derive(Debug)]
struct AccountedPoolMember {
    state: PoolCapacityState,
    cpu_millicores: u64,
    memory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolCapacityState {
    Reserved,
    Ready,
}

/// Atomic capacity accounting private to one supervisor.
#[derive(Debug, Clone)]
pub(crate) struct CapacityLedger {
    state: Arc<Mutex<CapacityState>>,
}

#[derive(Debug)]
pub(crate) struct WorkspaceCapacityReservation {
    ledger: Arc<Mutex<CapacityState>>,
    entry_id: Option<CapacityEntryId>,
}

#[derive(Debug)]
pub(crate) struct RegisteredWorkspaceCapacityGuard {
    ledger: Arc<Mutex<CapacityState>>,
    entry_id: Option<CapacityEntryId>,
}

#[derive(Debug)]
pub(crate) struct PoolCapacityReservation {
    ledger: Arc<Mutex<CapacityState>>,
    entry_id: Option<CapacityEntryId>,
}

#[derive(Debug)]
pub(crate) struct ReadyPoolCapacityGuard {
    ledger: Arc<Mutex<CapacityState>>,
    entry_id: Option<CapacityEntryId>,
}

impl CapacityLedger {
    pub(crate) fn new(configured_workspace_ceiling: u32) -> Self {
        Self {
            state: Arc::new(Mutex::new(CapacityState {
                revision: 0,
                faulted: false,
                configured_workspace_ceiling,
                next_pool_id: 0,
                workspaces: BTreeMap::new(),
                pool_entries: BTreeMap::new(),
            })),
        }
    }

    pub(crate) fn reserve_workspace(
        &self,
        id: &str,
        cpu_millicores: u64,
        memory_bytes: u64,
    ) -> Result<WorkspaceCapacityReservation, CapacityError> {
        let entry_id = CapacityEntryId::Workspace(id.to_string());
        let mut state = self.lock()?;
        ensure_healthy(&state)?;
        ensure_capacity(&state)?;
        let next_revision = preflight_next_revision(&mut state)?;
        if state.workspaces.contains_key(&entry_id) {
            return Err(CapacityError::DuplicateWorkspace);
        }
        state.workspaces.insert(
            entry_id.clone(),
            AccountedWorkspace {
                state: WorkspaceCapacityState::Reserved,
                cpu_millicores,
                memory_bytes,
            },
        );
        commit_revision(&mut state, next_revision);
        Ok(WorkspaceCapacityReservation {
            ledger: Arc::clone(&self.state),
            entry_id: Some(entry_id),
        })
    }

    /// Reserve at most `requested` pool entries in one atomic ledger lock.
    ///
    /// A full ledger is a normal refill condition, so it returns an empty
    /// batch without changing the revision. Every returned reservation owns
    /// exactly one newly recorded entry.
    pub(crate) fn reserve_pool_batch(
        &self,
        requested: usize,
        cpu_millicores: u64,
        memory_bytes: u64,
    ) -> Result<Vec<PoolCapacityReservation>, CapacityError> {
        let mut state = self.lock()?;
        ensure_healthy(&state)?;
        let used = entry_count(&state)?;
        let ceiling = usize::try_from(state.configured_workspace_ceiling)
            .map_err(|_| CapacityError::ArithmeticOverflow)?;
        let count = requested.min(
            ceiling
                .checked_sub(used)
                .ok_or(CapacityError::ArithmeticOverflow)?,
        );
        if count == 0 {
            return Ok(Vec::new());
        }

        // Preflight both mutable counters. From here every per-entry checked
        // increment is known to succeed, so a reported error cannot leave a
        // partial batch in the ledger.
        let count_u64 = u64::try_from(count).map_err(|_| CapacityError::ArithmeticOverflow)?;
        state
            .next_pool_id
            .checked_add(count_u64)
            .ok_or(CapacityError::ArithmeticOverflow)?;
        preflight_revision_range(&mut state, count_u64)?;

        let mut reservations = Vec::with_capacity(count);
        for _ in 0..count {
            let pool_id = state.next_pool_id;
            state.next_pool_id = state
                .next_pool_id
                .checked_add(1)
                .ok_or(CapacityError::ArithmeticOverflow)?;
            let entry_id = CapacityEntryId::Pool(pool_id);
            let next_revision = preflight_next_revision(&mut state)?;
            state.pool_entries.insert(
                entry_id.clone(),
                AccountedPoolMember {
                    state: PoolCapacityState::Reserved,
                    cpu_millicores,
                    memory_bytes,
                },
            );
            commit_revision(&mut state, next_revision);
            reservations.push(PoolCapacityReservation {
                ledger: Arc::clone(&self.state),
                entry_id: Some(entry_id),
            });
        }
        Ok(reservations)
    }

    pub(crate) fn snapshot(
        &self,
        profile: ExecutionProfile,
    ) -> Result<RunnerCapacity, CapacityError> {
        let state = self.lock()?;
        ensure_healthy(&state)?;
        let mut registered_workspaces = 0_u32;
        let mut runnable_workspaces = 0_u32;
        let mut resident_workspaces = 0_u32;
        let mut warm_pool_reserved_slots = 0_u32;
        let mut allocated_cpu_millicores = 0_u64;
        let mut allocated_memory_bytes = 0_u64;
        for workspace in state.workspaces.values() {
            if let WorkspaceCapacityState::Registered(workspace_state) = workspace.state {
                registered_workspaces = registered_workspaces
                    .checked_add(1)
                    .ok_or(CapacityError::ArithmeticOverflow)?;
                resident_workspaces = resident_workspaces
                    .checked_add(1)
                    .ok_or(CapacityError::ArithmeticOverflow)?;
                if workspace_state == WorkspaceState::Running {
                    runnable_workspaces = runnable_workspaces
                        .checked_add(1)
                        .ok_or(CapacityError::ArithmeticOverflow)?;
                }
                allocated_cpu_millicores = allocated_cpu_millicores
                    .checked_add(workspace.cpu_millicores)
                    .ok_or(CapacityError::ArithmeticOverflow)?;
                allocated_memory_bytes = allocated_memory_bytes
                    .checked_add(workspace.memory_bytes)
                    .ok_or(CapacityError::ArithmeticOverflow)?;
            }
        }
        for pool_entry in state.pool_entries.values() {
            warm_pool_reserved_slots = warm_pool_reserved_slots
                .checked_add(1)
                .ok_or(CapacityError::ArithmeticOverflow)?;
            if pool_entry.state == PoolCapacityState::Ready {
                resident_workspaces = resident_workspaces
                    .checked_add(1)
                    .ok_or(CapacityError::ArithmeticOverflow)?;
            }
            allocated_cpu_millicores = allocated_cpu_millicores
                .checked_add(pool_entry.cpu_millicores)
                .ok_or(CapacityError::ArithmeticOverflow)?;
            allocated_memory_bytes = allocated_memory_bytes
                .checked_add(pool_entry.memory_bytes)
                .ok_or(CapacityError::ArithmeticOverflow)?;
        }
        let capacity = RunnerCapacity {
            revision: state.revision,
            configured_workspace_ceiling: state.configured_workspace_ceiling,
            registered_workspaces,
            resident_workspaces,
            runnable_workspaces,
            allocated_cpu_millicores,
            allocated_memory_bytes,
            warm_pool_reserved_slots,
            profiles: vec![profile],
            operations: supported_operations(profile),
        };
        capacity.validate()?;
        Ok(capacity)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CapacityState>, CapacityError> {
        self.state.lock().map_err(|_| CapacityError::Poisoned)
    }

    #[cfg(test)]
    pub(crate) fn force_revision_for_test(&self, revision: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.revision = revision;
        }
    }

    /// Stop reporting inventory when a live resource cannot be reconciled.
    /// This is intentionally terminal: admitting another process while an
    /// earlier one may still be alive would publish false capacity.
    pub(crate) fn fail_closed(&self) {
        fault_ledger(&self.state);
    }
}

impl WorkspaceCapacityReservation {
    pub(crate) fn register(
        mut self,
        state: WorkspaceState,
    ) -> Result<RegisteredWorkspaceCapacityGuard, CapacityError> {
        self.register_in_place(state)
    }

    /// Promote this reservation without surrendering it on a failed
    /// transition. Pending runtime owners use this so process teardown stays
    /// ahead of capacity release even when ledger registration faults.
    pub(crate) fn register_in_place(
        &mut self,
        state: WorkspaceState,
    ) -> Result<RegisteredWorkspaceCapacityGuard, CapacityError> {
        let entry_id = self.entry_id.clone().ok_or(CapacityError::MissingEntry)?;
        let mut ledger = self.ledger.lock().map_err(|_| CapacityError::Poisoned)?;
        ensure_healthy(&ledger)?;
        let existing = ledger
            .workspaces
            .get(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        if existing.state != WorkspaceCapacityState::Reserved {
            return Err(CapacityError::InvalidTransition);
        }
        let next_revision = preflight_next_revision(&mut ledger)?;
        let workspace = ledger
            .workspaces
            .get_mut(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        workspace.state = WorkspaceCapacityState::Registered(state);
        commit_revision(&mut ledger, next_revision);
        self.entry_id = None;
        Ok(RegisteredWorkspaceCapacityGuard {
            ledger: Arc::clone(&self.ledger),
            entry_id: Some(entry_id),
        })
    }

    pub(crate) fn fail_closed(&self) {
        fault_ledger(&self.ledger);
    }
}

impl RegisteredWorkspaceCapacityGuard {
    pub(crate) fn set_state(&mut self, state: WorkspaceState) -> Result<(), CapacityError> {
        let entry_id = self.entry_id.as_mut().ok_or(CapacityError::MissingEntry)?;
        let mut ledger = self.ledger.lock().map_err(|_| CapacityError::Poisoned)?;
        ensure_healthy(&ledger)?;
        let existing = ledger
            .workspaces
            .get(&*entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        let WorkspaceCapacityState::Registered(current) = existing.state else {
            return Err(CapacityError::InvalidTransition);
        };
        if current == state {
            return Ok(());
        }
        let next_revision = preflight_next_revision(&mut ledger)?;
        let workspace = ledger
            .workspaces
            .get_mut(&*entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        workspace.state = WorkspaceCapacityState::Registered(state);
        commit_revision(&mut ledger, next_revision);
        Ok(())
    }

    pub(crate) fn fail_closed(&self) {
        fault_ledger(&self.ledger);
    }
}

impl PoolCapacityReservation {
    #[allow(dead_code)] // direct guard-transfer tests use this convenience API
    pub(crate) fn ready(mut self) -> Result<ReadyPoolCapacityGuard, CapacityError> {
        self.ready_in_place()
    }

    pub(crate) fn ready_in_place(&mut self) -> Result<ReadyPoolCapacityGuard, CapacityError> {
        let entry_id = self.entry_id.clone().ok_or(CapacityError::MissingEntry)?;
        let mut ledger = self.ledger.lock().map_err(|_| CapacityError::Poisoned)?;
        ensure_healthy(&ledger)?;
        let existing = ledger
            .pool_entries
            .get(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        if existing.state != PoolCapacityState::Reserved {
            return Err(CapacityError::InvalidTransition);
        }
        let next_revision = preflight_next_revision(&mut ledger)?;
        let pool_entry = ledger
            .pool_entries
            .get_mut(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        pool_entry.state = PoolCapacityState::Ready;
        commit_revision(&mut ledger, next_revision);
        self.entry_id = None;
        Ok(ReadyPoolCapacityGuard {
            ledger: Arc::clone(&self.ledger),
            entry_id: Some(entry_id),
        })
    }

    pub(crate) fn fail_closed(&self) {
        fault_ledger(&self.ledger);
    }
}

impl ReadyPoolCapacityGuard {
    #[allow(dead_code)] // direct guard-transfer tests use this convenience API
    pub(crate) fn adopt(
        mut self,
        workspace_id: &str,
        state: WorkspaceState,
    ) -> Result<RegisteredWorkspaceCapacityGuard, CapacityError> {
        self.adopt_in_place(workspace_id, state)
    }

    pub(crate) fn adopt_in_place(
        &mut self,
        workspace_id: &str,
        state: WorkspaceState,
    ) -> Result<RegisteredWorkspaceCapacityGuard, CapacityError> {
        let entry_id = self.entry_id.clone().ok_or(CapacityError::MissingEntry)?;
        let workspace_entry_id = CapacityEntryId::Workspace(workspace_id.to_string());
        let mut ledger = self.ledger.lock().map_err(|_| CapacityError::Poisoned)?;
        ensure_healthy(&ledger)?;
        if ledger.workspaces.contains_key(&workspace_entry_id) {
            return Err(CapacityError::DuplicateWorkspace);
        }
        let pool_entry = ledger
            .pool_entries
            .get(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        if pool_entry.state != PoolCapacityState::Ready {
            return Err(CapacityError::InvalidTransition);
        }
        let next_revision = preflight_next_revision(&mut ledger)?;
        let pool_entry = ledger
            .pool_entries
            .remove(&entry_id)
            .ok_or(CapacityError::MissingEntry)?;
        ledger.workspaces.insert(
            workspace_entry_id.clone(),
            AccountedWorkspace {
                state: WorkspaceCapacityState::Registered(state),
                cpu_millicores: pool_entry.cpu_millicores,
                memory_bytes: pool_entry.memory_bytes,
            },
        );
        commit_revision(&mut ledger, next_revision);
        self.entry_id = None;
        Ok(RegisteredWorkspaceCapacityGuard {
            ledger: Arc::clone(&self.ledger),
            entry_id: Some(workspace_entry_id),
        })
    }

    pub(crate) fn fail_closed(&self) {
        fault_ledger(&self.ledger);
    }
}

fn fault_ledger(ledger: &Arc<Mutex<CapacityState>>) {
    if let Ok(mut state) = ledger.lock() {
        state.faulted = true;
    }
}

fn ensure_capacity(state: &CapacityState) -> Result<(), CapacityError> {
    let used = entry_count(state)?;
    if used
        >= usize::try_from(state.configured_workspace_ceiling)
            .map_err(|_| CapacityError::ArithmeticOverflow)?
    {
        return Err(CapacityError::Exhausted);
    }
    Ok(())
}

fn entry_count(state: &CapacityState) -> Result<usize, CapacityError> {
    state
        .workspaces
        .len()
        .checked_add(state.pool_entries.len())
        .ok_or(CapacityError::ArithmeticOverflow)
}

fn ensure_healthy(state: &CapacityState) -> Result<(), CapacityError> {
    if state.faulted {
        Err(CapacityError::Faulted)
    } else {
        Ok(())
    }
}

/// Reserve the next externally visible revision before a ledger mutation.
///
/// Revision exhaustion is terminal because an unversioned mutation could make
/// a prior inventory snapshot appear current. Callers commit the returned
/// value only after their map or entry mutation succeeds.
fn preflight_next_revision(state: &mut CapacityState) -> Result<u64, CapacityError> {
    ensure_healthy(state)?;
    state.revision.checked_add(1).ok_or_else(|| {
        state.faulted = true;
        CapacityError::Faulted
    })
}

/// Verify that an atomic batch can publish every per-entry revision before it
/// changes an id counter or inserts its first entry.
fn preflight_revision_range(state: &mut CapacityState, count: u64) -> Result<(), CapacityError> {
    ensure_healthy(state)?;
    if state.revision.checked_add(count).is_none() {
        state.faulted = true;
        return Err(CapacityError::Faulted);
    }
    Ok(())
}

fn commit_revision(state: &mut CapacityState, next_revision: u64) {
    state.revision = next_revision;
}

fn supported_operations(profile: ExecutionProfile) -> Vec<WorkspaceOperation> {
    [
        WorkspaceOperation::Create,
        WorkspaceOperation::Destroy,
        WorkspaceOperation::Execute,
        WorkspaceOperation::WriteFile,
        WorkspaceOperation::ReadFile,
        WorkspaceOperation::Pause,
        WorkspaceOperation::Resume,
        WorkspaceOperation::Snapshot,
        WorkspaceOperation::Restore,
        WorkspaceOperation::Fork,
        WorkspaceOperation::WarmPool,
        WorkspaceOperation::Ingress,
        WorkspaceOperation::Attest,
    ]
    .into_iter()
    .filter(|operation| profile.supports(*operation))
    .collect()
}

fn release_entry(ledger: &Arc<Mutex<CapacityState>>, owned_entry_id: &mut Option<CapacityEntryId>) {
    let Some(entry_id) = owned_entry_id.as_ref() else {
        return;
    };
    let Ok(mut state) = ledger.lock() else {
        return;
    };
    let Ok(next_revision) = preflight_next_revision(&mut state) else {
        // Drop cannot report overflow. Keep its entry internally and reject
        // every later observation or admission rather than publishing stale
        // normal inventory.
        return;
    };
    let removed = match entry_id {
        CapacityEntryId::Workspace(_) => state.workspaces.remove(entry_id).is_some(),
        CapacityEntryId::Pool(_) => state.pool_entries.remove(entry_id).is_some(),
    };
    if removed {
        commit_revision(&mut state, next_revision);
        *owned_entry_id = None;
    }
}

impl Drop for WorkspaceCapacityReservation {
    fn drop(&mut self) {
        release_entry(&self.ledger, &mut self.entry_id);
    }
}
impl Drop for RegisteredWorkspaceCapacityGuard {
    fn drop(&mut self) {
        release_entry(&self.ledger, &mut self.entry_id);
    }
}
impl Drop for PoolCapacityReservation {
    fn drop(&mut self) {
        release_entry(&self.ledger, &mut self.entry_id);
    }
}
impl Drop for ReadyPoolCapacityGuard {
    fn drop(&mut self) {
        release_entry(&self.ledger, &mut self.entry_id);
    }
}

#[cfg(test)]
mod tests {
    use super::CapacityLedger;
    use ne_protocol::profile::ExecutionProfile;
    use ne_protocol::supervisor::WorkspaceState;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Break caught: removing reservation accounting would allow two resident
    // entries at a one-workspace ceiling.
    #[test]
    fn capacity_ledger_rejects_a_reservation_at_the_resident_ceiling() {
        let ledger = CapacityLedger::new(1);
        let _workspace = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("first reservation");
        let reservations = ledger
            .reserve_pool_batch(1, 1_000, 1_024)
            .expect("full pool tick is a no-op");
        assert!(reservations.is_empty());
    }

    // Break caught: treating a pool-to-registry handoff as a new allocation
    // would increase resident capacity or resource totals.
    #[test]
    fn capacity_ledger_adoption_is_count_neutral() {
        let ledger = CapacityLedger::new(2);
        let ready = ledger
            .reserve_pool_batch(1, 2_000, 2_048)
            .expect("pool reservation")
            .pop()
            .expect("one pool reservation")
            .ready()
            .expect("ready pool member");
        let before = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("pool snapshot");
        let _workspace = ready
            .adopt("ws-1", WorkspaceState::Running)
            .expect("adopt pool member");
        let after = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("workspace snapshot");
        assert_eq!(before.resident_workspaces, 1);
        assert_eq!(after.resident_workspaces, 1);
        assert_eq!(
            before.allocated_cpu_millicores,
            after.allocated_cpu_millicores
        );
        assert_eq!(before.allocated_memory_bytes, after.allocated_memory_bytes);
        assert_eq!(after.registered_workspaces, 1);
    }

    // Break caught: a partial warm-pool refill must retain the available
    // reservation rather than roll it back or churn the revision on retry.
    #[test]
    fn pool_batch_uses_only_remaining_headroom_without_revision_churn() {
        let ledger = CapacityLedger::new(2);
        let _workspace = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("workspace reservation")
            .register(WorkspaceState::Running)
            .expect("workspace registration");

        let permits = ledger
            .reserve_pool_batch(2, 1_000, 1_024)
            .expect("partial pool reservation");
        assert_eq!(permits.len(), 1);
        let after_partial = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("partial snapshot");
        assert_eq!(after_partial.warm_pool_reserved_slots, 1);

        let empty = ledger
            .reserve_pool_batch(2, 1_000, 1_024)
            .expect("full pool returns no reservations");
        assert!(empty.is_empty());
        let after_retry = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("retry snapshot");
        assert_eq!(after_retry.revision, after_partial.revision);
    }

    // Break caught: a release at revision overflow must not silently expose
    // stale inventory or accept later mutations.
    #[test]
    fn release_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(1);
        let reservation = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("workspace reservation");
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        drop(reservation);

        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.reserve_workspace("ws-2", 1_000, 1_024),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: an explicit workspace reservation that cannot publish its
    // revision must not leave a usable ledger with an unreported mutation.
    #[test]
    fn workspace_reserve_revision_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(2);
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        assert!(matches!(
            ledger.reserve_workspace("ws-1", 1_000, 1_024),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.reserve_pool_batch(1, 1_000, 1_024),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: registering after a revision overflow must fail closed
    // before changing the reservation into public inventory.
    #[test]
    fn workspace_register_revision_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(1);
        let reservation = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("reservation");
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        assert!(matches!(
            reservation.register(WorkspaceState::Running),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.reserve_workspace("ws-2", 1_000, 1_024),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: a state update without an available revision must not
    // expose a new state while keeping normal admission active.
    #[test]
    fn workspace_state_revision_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(1);
        let mut guard = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("reservation")
            .register(WorkspaceState::Running)
            .expect("registration");
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        assert!(matches!(
            guard.set_state(WorkspaceState::Paused),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: a pool ready transition that cannot publish its revision
    // must fault the ledger instead of reporting arithmetic overflow only.
    #[test]
    fn pool_ready_revision_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(1);
        let reservation = ledger
            .reserve_pool_batch(1, 1_000, 1_024)
            .expect("pool reservation")
            .pop()
            .expect("one reservation");
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        assert!(matches!(
            reservation.ready(),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: pool adoption must never move the entry into the registry
    // if its revision cannot be recorded.
    #[test]
    fn pool_adopt_revision_overflow_faults_the_ledger() {
        let ledger = CapacityLedger::new(1);
        let ready = ledger
            .reserve_pool_batch(1, 1_000, 1_024)
            .expect("pool reservation")
            .pop()
            .expect("one reservation")
            .ready()
            .expect("ready member");
        ledger.state.lock().expect("test lock").revision = u64::MAX;

        assert!(matches!(
            ready.adopt("ws-1", WorkspaceState::Running),
            Err(super::CapacityError::Faulted)
        ));
        assert!(matches!(
            ledger.snapshot(ExecutionProfile::Standard),
            Err(super::CapacityError::Faulted)
        ));
    }

    // Break caught: batch preflight must fault rather than insert a partial
    // batch when the revision range cannot represent every reservation.
    #[test]
    fn pool_batch_revision_overflow_faults_without_entries() {
        let ledger = CapacityLedger::new(2);
        ledger.state.lock().expect("test lock").revision = u64::MAX - 1;

        assert!(matches!(
            ledger.reserve_pool_batch(2, 1_000, 1_024),
            Err(super::CapacityError::Faulted)
        ));
        let state = ledger.state.lock().expect("test lock");
        assert!(state.pool_entries.is_empty());
        assert!(state.workspaces.is_empty());
        assert!(state.faulted);
    }

    // Break caught: a live snapshot swap that replaces a paused instance must
    // report it runnable only after the capacity guard transitions.
    #[test]
    fn hot_swap_transitions_the_registered_guard_to_running() {
        let ledger = CapacityLedger::new(1);
        let mut guard = ledger
            .reserve_workspace("ws-1", 1_000, 1_024)
            .expect("reservation")
            .register(WorkspaceState::Paused)
            .expect("paused registration");
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("paused snapshot")
                .runnable_workspaces,
            0
        );
        guard
            .set_state(WorkspaceState::Running)
            .expect("successful swap transition");
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("running snapshot")
                .runnable_workspaces,
            1
        );
    }

    // Break caught: changing any lifecycle transition or release revision,
    // or exposing reserved workspace resources in public inventory.
    #[test]
    fn lifecycle_revisions_and_public_inventory_are_exact() {
        let ledger = CapacityLedger::new(3);
        let snapshot = |revision, registered, resident, runnable, cpu, memory, pool_slots| {
            let capacity = ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("valid snapshot");
            assert_eq!(capacity.revision, revision);
            assert_eq!(capacity.registered_workspaces, registered);
            assert_eq!(capacity.resident_workspaces, resident);
            assert_eq!(capacity.runnable_workspaces, runnable);
            assert_eq!(capacity.allocated_cpu_millicores, cpu);
            assert_eq!(capacity.allocated_memory_bytes, memory);
            assert_eq!(capacity.warm_pool_reserved_slots, pool_slots);
        };
        snapshot(0, 0, 0, 0, 0, 0, 0);
        let reservation = ledger
            .reserve_workspace("workspace", 2_000, 3_072)
            .expect("workspace reserve");
        snapshot(1, 0, 0, 0, 0, 0, 0);
        let mut workspace = reservation
            .register(WorkspaceState::Running)
            .expect("workspace register");
        snapshot(2, 1, 1, 1, 2_000, 3_072, 0);
        workspace.set_state(WorkspaceState::Paused).expect("paused");
        snapshot(3, 1, 1, 0, 2_000, 3_072, 0);
        workspace
            .set_state(WorkspaceState::Snapshotting)
            .expect("snapshotting");
        snapshot(4, 1, 1, 0, 2_000, 3_072, 0);
        workspace
            .set_state(WorkspaceState::Running)
            .expect("running");
        snapshot(5, 1, 1, 1, 2_000, 3_072, 0);
        drop(workspace);
        snapshot(6, 0, 0, 0, 0, 0, 0);

        let pool = ledger
            .reserve_pool_batch(1, 1_000, 2_048)
            .expect("pool reserve")
            .pop()
            .expect("one pool reservation");
        snapshot(7, 0, 0, 0, 1_000, 2_048, 1);
        let ready = pool.ready().expect("ready");
        snapshot(8, 0, 1, 0, 1_000, 2_048, 1);
        drop(ready);
        snapshot(9, 0, 0, 0, 0, 0, 0);

        let ready = ledger
            .reserve_pool_batch(1, 4_000, 8_192)
            .expect("second pool reserve")
            .pop()
            .expect("one second reservation")
            .ready()
            .expect("second ready");
        snapshot(11, 0, 1, 0, 4_000, 8_192, 1);
        let adopted = ready
            .adopt("adopted", WorkspaceState::Running)
            .expect("adopt");
        snapshot(12, 1, 1, 1, 4_000, 8_192, 0);
        drop(adopted);
        snapshot(13, 0, 0, 0, 0, 0, 0);
    }

    #[test]
    fn failed_operations_and_same_state_leave_snapshot_unchanged() {
        let ledger = CapacityLedger::new(2);
        let reservation = ledger
            .reserve_workspace("workspace", 1_000, 1_024)
            .expect("workspace reserve");
        let before = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("before failures");
        assert!(matches!(
            ledger.reserve_workspace("workspace", 1_000, 1_024),
            Err(super::CapacityError::DuplicateWorkspace)
        ));
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("after duplicate"),
            before
        );
        let _other = ledger
            .reserve_workspace("other", 1_000, 1_024)
            .expect("fill remaining capacity");
        let before_full_batch = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("before full batch");
        assert!(
            ledger
                .reserve_pool_batch(1, 1_000, 1_024)
                .expect("full batch no-op")
                .is_empty()
        );
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("after failures"),
            before_full_batch
        );
        let mut guard = reservation
            .register(WorkspaceState::Running)
            .expect("register");
        let before_same_state = ledger
            .snapshot(ExecutionProfile::Standard)
            .expect("before no-op");
        guard
            .set_state(WorkspaceState::Running)
            .expect("same state");
        assert_eq!(
            ledger
                .snapshot(ExecutionProfile::Standard)
                .expect("after no-op"),
            before_same_state
        );
    }

    #[test]
    fn concurrent_lifecycle_mutations_always_publish_valid_snapshots() {
        let ledger = Arc::new(CapacityLedger::new(16));
        let done = Arc::new(AtomicBool::new(false));
        let sampler_ledger = Arc::clone(&ledger);
        let sampler_done = Arc::clone(&done);
        let sampler = std::thread::spawn(move || {
            while !sampler_done.load(Ordering::Acquire) {
                let snapshot = sampler_ledger
                    .snapshot(ExecutionProfile::Standard)
                    .expect("sampler must not observe a fault or poison");
                snapshot.validate().expect("wire-valid snapshot");
                assert!(snapshot.registered_workspaces <= snapshot.resident_workspaces);
                assert!(snapshot.runnable_workspaces <= snapshot.registered_workspaces);
                assert!(
                    snapshot.registered_workspaces + snapshot.warm_pool_reserved_slots
                        <= snapshot.configured_workspace_ceiling
                );
                assert!(snapshot.allocated_cpu_millicores <= 1_000_000_000);
                assert!(snapshot.allocated_memory_bytes <= (1_u64 << 50));
            }
        });
        let mut workers = Vec::new();
        for worker in 0..4 {
            let ledger = Arc::clone(&ledger);
            workers.push(std::thread::spawn(move || {
                for iteration in 0..12 {
                    let workspace_id = format!("ws-{worker}-{iteration}");
                    let mut workspace = ledger
                        .reserve_workspace(&workspace_id, 1_000, 1_024)
                        .expect("workspace reserve")
                        .register(WorkspaceState::Running)
                        .expect("workspace register");
                    workspace.set_state(WorkspaceState::Paused).expect("pause");
                    workspace
                        .set_state(WorkspaceState::Snapshotting)
                        .expect("snapshotting");
                    workspace
                        .set_state(WorkspaceState::Running)
                        .expect("running");
                    drop(workspace);

                    let pool = ledger
                        .reserve_pool_batch(1, 2_000, 2_048)
                        .expect("pool reserve")
                        .pop()
                        .expect("one pool reservation")
                        .ready()
                        .expect("pool ready");
                    let adopted = pool
                        .adopt(
                            &format!("pool-{worker}-{iteration}"),
                            WorkspaceState::Running,
                        )
                        .expect("pool adoption");
                    drop(adopted);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("worker must not panic");
        }
        done.store(true, Ordering::Release);
        sampler.join().expect("sampler must not panic");
    }
}
