// Integration Test Suite for Aura DecentralTrust
//
// This module contains all integration tests organized by functionality:
// - api_tests: REST API endpoint testing  
// - cli_tests: Binary/CLI interface testing
// - unit_integration_tests: Cross-crate integration without running services
// - workflow_tests: End-to-end workflow testing with full stack

pub mod api_tests;
pub mod cli_tests;
pub mod unit_integration_tests;
pub mod workflow_tests;