#!/bin/bash
# Script to generate secure configuration for Aura Node

echo "🔐 Generating secure configuration for Aura Node..."

# Check if .env already exists
if [ -f .env ]; then
    echo "⚠️  .env file already exists. Backing up to .env.backup"
    cp .env .env.backup
fi

# Generate secure JWT secret
JWT_SECRET=$(openssl rand -base64 32)

# Create .env file
cat > .env << EOF
# Aura Node Environment Configuration
# Generated on $(date)

# SECURITY SETTINGS
AURA_JWT_SECRET=$JWT_SECRET

# Node Configuration
NODE_TYPE=validator
NODE_ID=node-$(openssl rand -hex 4)
API_ADDR=127.0.0.1:8080

# TLS Configuration
ENABLE_TLS=false
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem

# Database Configuration
DB_PATH=./data/db

# P2P Network Configuration
P2P_PORT=9000
BOOTSTRAP_PEERS=

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60
MAX_REQUESTS_PER_HOUR=1000

# Logging
RUST_LOG=info,aura_node=debug
EOF

echo "✅ Created .env file with secure JWT secret"

# Generate secure node credentials
mkdir -p config

cat > config/credentials.json << EOF
{
  "validator-node-1": {
    "password_hash": "$(echo -n 'CHANGE-ME-$(openssl rand -hex 16)' | sha256sum | cut -d' ' -f1)",
    "role": "validator"
  },
  "query-node-1": {
    "password_hash": "$(echo -n 'CHANGE-ME-$(openssl rand -hex 16)' | sha256sum | cut -d' ' -f1)",
    "role": "query"
  }
}
EOF

echo "✅ Created config/credentials.json with secure password hashes"

# Set appropriate permissions
chmod 600 .env
chmod 600 config/credentials.json

echo "
🎉 Secure configuration generated successfully!

⚠️  IMPORTANT NEXT STEPS:
1. Update the passwords in config/credentials.json (currently set to random values)
2. To set a password, compute its SHA256 hash:
   echo -n 'your-password' | sha256sum | cut -d' ' -f1
3. Enable TLS in production by setting ENABLE_TLS=true
4. Review and adjust rate limiting settings
5. Configure bootstrap peers for P2P network

📝 Files created:
- .env (with secure JWT secret)
- config/credentials.json (with placeholder credentials)

🔒 Security checklist:
[ ] Change default passwords in credentials.json
[ ] Enable TLS for production
[ ] Set up firewall rules
[ ] Configure secure backup of JWT secret
[ ] Review rate limiting settings
"