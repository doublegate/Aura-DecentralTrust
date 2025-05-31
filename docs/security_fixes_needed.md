# Security Fixes Needed

## Critical (Must fix before production) ✅
- [x] Replace hardcoded JWT secret in auth.rs with environment variable
- [x] Remove hardcoded test credentials from auth.rs

## High Priority ✅
- [x] Add message size validation to P2P network handler
- [x] Replace unwrap()/expect() with proper error handling in critical paths
- [x] Implement actual rate limiting (not just constants)

## Medium Priority ✅
- [x] Implement mutual TLS for node-to-node communication
- [x] Add comprehensive SSRF protection in URL validation
- [x] Verify transaction signatures in API endpoints
- [x] Avoid plaintext copies during encryption

## Low Priority ✅
- [x] Add audit logging for security events
- [x] Implement certificate pinning for P2P
- [x] Set proper file permissions on Windows
- [x] Sanitize error messages returned to clients
