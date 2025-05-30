# RocksDB Build Guide for Modern Linux

This guide documents build requirements and solutions for compiling Aura with RocksDB on modern Linux systems (Fedora 42/Bazzite).

## System Requirements

### Required Development Packages

Install these packages before building:

```bash
# Fedora/RHEL/Bazzite
sudo dnf install -y \
  gcc \
  gcc-c++ \
  clang \
  clang-devel \
  glibc-devel \
  libzstd-devel \
  rocksdb-devel \
  snappy-devel \
  lz4-devel \
  bzip2-devel \
  zlib-devel

# Ubuntu/Debian
sudo apt-get install -y \
  build-essential \
  clang \
  libclang-dev \
  librocksdb-dev \
  libzstd-dev \
  libsnappy-dev \
  liblz4-dev \
  libbz2-dev \
  zlib1g-dev
```

## Build Environment Setup

### Environment Variables

For systems with non-standard GCC installations or bindgen issues:

```bash
# Find your GCC include path
gcc -print-search-dirs | grep install

# Set environment variables
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include"
export ZSTD_SYS_USE_PKG_CONFIG=1
export ROCKSDB_LIB_DIR=/usr/lib64  # Adjust based on your system
```

### Build Commands

```bash
# Standard build
cargo build --release

# With environment variables (if needed)
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-redhat-linux/15/include" \
ZSTD_SYS_USE_PKG_CONFIG=1 \
cargo build --release

# Enable static linking (optional, for better portability)
ROCKSDB_STATIC=1 cargo build --release
```

## Common Build Issues and Solutions

### 1. Missing C++ Headers

**Error**: `fatal error: 'cstddef' file not found`

**Solution**: Install GCC C++ development headers:
```bash
sudo dnf install gcc-c++ glibc-devel
```

### 2. Bindgen Cannot Find Standard Headers

**Error**: `bindgen` unable to find standard C headers

**Solution**: Set `BINDGEN_EXTRA_CLANG_ARGS` to point to GCC includes:
```bash
export BINDGEN_EXTRA_CLANG_ARGS="-I$(gcc -print-file-name=include)"
```

### 3. RocksDB Linking Errors

**Error**: `cannot find -lrocksdb`

**Solution**: 
- Install rocksdb-devel package
- Or build RocksDB from source and set `ROCKSDB_LIB_DIR`

### 4. Version Compatibility

Ensure compatible versions:
- rust-rocksdb 0.21.0 (as specified in Cargo.toml)
- System RocksDB 6.x or 7.x
- GCC 11+ (for C++17 support)

## Dependency Version Matrix

Based on learnings from build-fixes-sled branch:

| Dependency | Version | Notes |
|------------|---------|-------|
| bincode | 1.3.3 | Stay on v1 for now, v2 requires API changes |
| rand | 0.8.5 | Don't use 0.9.x, causes compatibility issues |
| libp2p | 0.55.0 | Latest stable |
| axum | 0.8.0 | Use `axum::serve` instead of `Server::bind` |
| ed25519-dalek | 2.1.1 | Enable "serde" feature |
| serde_json | 1.0 | Add to aura-crypto if needed |

## Performance Considerations

### RocksDB Configuration

For optimal blockchain performance:

```rust
let mut opts = rocksdb::Options::default();
opts.create_if_missing(true);
opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
opts.increase_parallelism(num_cpus::get() as i32);
opts.set_max_open_files(10000);
opts.set_use_fsync(true);  // For data integrity
```

### Write Batch Operations

RocksDB supports atomic batch operations, critical for blockchain consistency:

```rust
let mut batch = WriteBatch::default();
batch.put(b"key1", b"value1");
batch.put(b"key2", b"value2");
batch.delete(b"old_key");
db.write(batch)?;  // Atomic operation
```

## Testing the Build

After successful compilation:

```bash
# Run tests
cargo test

# Run with verbose output
RUST_LOG=debug cargo run --bin aura-node

# Check specific features
cargo check --features rocksdb
```

## Troubleshooting Checklist

1. ✅ All system packages installed
2. ✅ Environment variables set (if needed)
3. ✅ Rust toolchain up to date (`rustup update`)
4. ✅ Clean build attempted (`cargo clean`)
5. ✅ Correct branch checked out
6. ✅ No conflicting global Rust packages

## Migration Notes

If coming from the sled branch:
- RocksDB provides better performance for blockchain workloads
- Atomic batch operations are natively supported
- No need for JSON serialization workarounds
- Better compression options available

## See Also

- [RocksDB Documentation](https://rocksdb.org/)
- [rust-rocksdb Crate](https://crates.io/crates/rocksdb)
- `to-dos/BUILD_FIXES_SUMMARY.md` - Alternative approaches tried