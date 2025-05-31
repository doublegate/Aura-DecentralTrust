# Configuration Directory

This directory contains configuration files for the Aura node.

## Files

- `config.example.toml` - Example configuration file with default values
- `config.toml` - Actual configuration file (not tracked in git)

## Usage

1. Copy `config.example.toml` to `config.toml`
2. Edit `config.toml` with your specific settings
3. Run the node with: `cargo run --bin aura-node`

The node will automatically use `config/config.toml` as the default configuration path.

You can also specify a custom config file location:
```bash
cargo run --bin aura-node --config /path/to/your/config.toml
```

## Configuration Options

See `config.example.toml` for all available configuration options and their descriptions.