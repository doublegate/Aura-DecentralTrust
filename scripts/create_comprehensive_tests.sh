#!/bin/bash
# Script to create comprehensive test coverage for all modules

set -e

echo "Creating comprehensive test coverage for Aura DecentralTrust"
echo "=========================================================="

# Function to check if a file has tests
has_tests() {
    grep -q "#\[cfg(test)\]" "$1" 2>/dev/null
}

# Function to add test module to a file
add_test_module() {
    local file=$1
    local module_name=$(basename "$file" .rs)
    
    if has_tests "$file"; then
        echo "✓ $file already has tests"
        return
    fi
    
    echo "→ Adding tests to $file"
    
    # Add test module at the end of the file
    cat >> "$file" << 'EOF'

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add comprehensive tests for all public functions
    // TODO: Add tests for error conditions
    // TODO: Add tests for edge cases
    // TODO: Add property-based tests where appropriate
}
EOF
    
    echo "✓ Added test module to $file"
}

# Process each crate
for crate in aura-common aura-crypto aura-ledger aura-wallet-core aura-node; do
    echo ""
    echo "Processing $crate..."
    echo "-------------------"
    
    if [ -d "$crate/src" ]; then
        # Find all .rs files except lib.rs and main.rs
        find "$crate/src" -name "*.rs" -type f ! -name "lib.rs" ! -name "main.rs" ! -name "mod.rs" | while read -r file; do
            add_test_module "$file"
        done
    fi
done

echo ""
echo "Running all tests to check compilation..."
echo "----------------------------------------"
cargo test --all --no-fail-fast

echo ""
echo "Test coverage creation complete!"
echo ""
echo "Next steps:"
echo "1. Fill in the TODO comments in each test module"
echo "2. Run 'cargo tarpaulin' to measure coverage"
echo "3. Aim for 100% coverage on all critical paths"