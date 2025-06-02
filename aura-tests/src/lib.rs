// Aura DecentralTrust Test Suite
//
// This crate consolidates all testing infrastructure for the Aura project:
// - Integration tests: API, CLI, workflows, and cross-crate integration
// - Property-based tests: Invariant verification using proptest
// - Performance benchmarks: Critical path performance measurements
//
// The test suite is organized to be easily maintainable and extensible
// as development continues.

#![cfg(test)]

/// Integration test modules
pub mod integration;

/// Property-based test modules
pub mod property;

// Performance benchmark modules
#[cfg(not(test))]
pub mod benchmarks;