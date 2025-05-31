# Security Notice

## Sensitive File Management

This project uses the following directories for sensitive data:

### `/secrets/`
- Contains authentication tokens and credentials
- NEVER commit files from this directory
- Excluded by .gitignore

### `/logs/`
- Contains execution and test logs
- May contain sensitive debugging information
- Excluded by .gitignore

### `/data/`
- Contains node data and TLS certificates
- Private keys have restricted permissions (400)
- Excluded by .gitignore

## Security Best Practices

1. **Never commit secrets** - All tokens, keys, and credentials must stay local
2. **Use environment variables** - For production credentials
3. **Rotate credentials regularly** - Especially after testing
4. **Clear test data** - Remove test tokens and logs after development sessions
5. **Check before committing** - Always run `git status` to verify no secrets are staged

## Test Credentials

Default test credentials (for development only):
- validator-node-1 / validator-password-1
- query-node-1 / query-password-1
- admin / admin-password

**IMPORTANT**: These MUST be changed before any deployment!

## TLS Certificates

Self-signed certificates are generated in `/data/`:
- `api-cert.pem` - Public certificate
- `api-key.pem` - Private key (chmod 400)

For production, use proper CA-signed certificates.

## Reporting Security Issues

Please report security vulnerabilities to: [Create security policy]