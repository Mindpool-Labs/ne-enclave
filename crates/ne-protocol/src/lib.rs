// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared types and protocol definitions for NeuronEdge Enclave.
//!
//! This crate is Apache-2.0. It provides compatibility types for the runtime and
//! optional external integrations. It must not depend on either side's internals.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod attestation;
pub mod audit;
pub mod guest;
pub mod profile;
pub mod snapshot;
pub mod supervisor;

pub use attestation::{
    PUBLIC_EVIDENCE_SCHEMA_VERSION, PublicAttestationError, PublicAttestationEvidence,
    PublicAttestationProof, PublicAttestationProvider,
};

#[cfg(feature = "grpc")]
pub mod grpc;
