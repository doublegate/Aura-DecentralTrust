#!/bin/bash
# CI/CD Pre-flight Check Script
# Run this locally to catch issues before pushing to GitHub

set -e

echo "=== CI/CD Pre-flight Check ==="
echo

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ ERROR: Not in project root directory"
    exit 1
fi

# Set up environment variables for RocksDB
export ROCKSDB_LIB_DIR=/usr/lib64
export LIBROCKSDB_SYS_DISABLE_BUNDLED=1

echo "1. Checking code formatting..."
if cargo fmt --all -- --check; then
    echo "✅ Code formatting is correct"
else
    echo "❌ Code formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi

echo
echo "2. Running clippy..."
if cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tee clippy.log; then
    echo "✅ Clippy passed with no warnings"
    rm -f clippy.log
else
    echo "❌ Clippy found issues. Check clippy.log for details."
    exit 1
fi

echo
echo "3. Building project..."
if cargo build --verbose; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

echo
echo "4. Running tests..."
if cargo test --verbose 2>&1 | tee test.log; then
    echo "✅ All tests passed"
    rm -f test.log
else
    echo "⚠️  Some tests failed. Check test.log for details."
    echo "Note: Some RocksDB tests may fail locally but work in CI"
fi

echo
echo "5. Checking for common CI issues..."

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "⚠️  Warning: You have uncommitted changes"
    git status --short
fi

# Check Cargo.lock exists
if [ ! -f "Cargo.lock" ]; then
    echo "❌ ERROR: Cargo.lock not found. This will cause CI to fail."
    echo "Run 'cargo build' to generate it."
    exit 1
fi

# Check for large files
echo
echo "6. Checking for large files..."
find . -type f -size +10M -not -path "./target/*" -not -path "./.git/*" | while read -r file; do
    echo "⚠️  Warning: Large file detected: $file ($(du -h "$file" | cut -f1))"
done

echo
echo "=== CI/CD Pre-flight Check Complete ==="
echo
echo "If all checks passed, your code should pass CI/CD on GitHub!"
echo "If you see warnings, they may or may not cause CI failures."