# Security Policy

## Supported Versions

Currently, Aura is in Phase 1 development. Security updates will be provided for:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The Aura team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

To report a security vulnerability, please DO NOT use the public issue tracker. Instead:

1. Email: security@aura-network.org (pending setup)
2. For now, contact the maintainers directly through GitHub

Please include:
- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Considerations in Aura

### Cryptographic Components
- All cryptographic operations use well-audited libraries
- Private keys are zeroized on drop
- Ed25519 for digital signatures
- AES-256-GCM for encryption
- SHA-256 and Blake3 for hashing

### Data Privacy
- The ledger stores NO personal data
- All PII is encrypted and stored off-chain
- DIDs provide pseudonymity
- Verifiable Credentials support selective disclosure

### Network Security
- libp2p provides encrypted P2P communication
- Noise protocol for transport security
- Peer authentication via cryptographic identities

### Best Practices for Contributors
1. Never commit secrets or private keys
2. Use the provided cryptographic primitives
3. Validate all external inputs
4. Follow the principle of least privilege
5. Keep dependencies updated

## Disclosure Policy

When we receive a security bug report, we will:
1. Confirm the problem and determine affected versions
2. Audit code to find similar problems
3. Prepare fixes for all supported releases
4. Release patches as soon as possible

We request that you:
- Give us reasonable time to fix the issue before public disclosure
- Make a good faith effort to avoid privacy violations and data destruction
- Not perform actions that could impact service availability

Thank you for helping keep Aura and our users safe!