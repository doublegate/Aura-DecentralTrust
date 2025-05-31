#!/usr/bin/env python3
"""
Script to generate comprehensive test coverage for all Rust source files.
This helps achieve 100% test coverage by identifying untested code paths.
"""

import os
import re
import sys
from pathlib import Path

# Test template for Rust modules
TEST_MODULE_TEMPLATE = """
#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add comprehensive tests for all public functions
    // TODO: Add tests for error conditions
    // TODO: Add tests for edge cases
    // TODO: Add property-based tests where appropriate
}
"""

def find_rust_files(directory):
    """Find all Rust source files that need tests."""
    rust_files = []
    for root, dirs, files in os.walk(directory):
        # Skip target and other build directories
        if 'target' in root or '.git' in root:
            continue
        for file in files:
            if file.endswith('.rs') and not file.endswith('mod.rs'):
                rust_files.append(os.path.join(root, file))
    return rust_files

def has_test_module(file_path):
    """Check if a Rust file already has a test module."""
    with open(file_path, 'r') as f:
        content = f.read()
    return '#[cfg(test)]' in content

def extract_functions(file_path):
    """Extract public functions from a Rust file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Simple regex to find public functions
    pub_fn_pattern = r'pub\s+(?:async\s+)?fn\s+(\w+)'
    functions = re.findall(pub_fn_pattern, content)
    return functions

def generate_test_suggestions(file_path):
    """Generate test suggestions based on the file content."""
    functions = extract_functions(file_path)
    suggestions = []
    
    for func in functions:
        suggestions.append(f"    #[test]\n    fn test_{func}() {{\n        // TODO: Implement test\n    }}")
    
    return "\n\n".join(suggestions)

def main():
    """Main function to analyze test coverage needs."""
    src_dirs = ['aura-common/src', 'aura-crypto/src', 'aura-ledger/src', 
                'aura-wallet-core/src', 'aura-node/src']
    
    files_needing_tests = []
    files_with_tests = []
    
    for src_dir in src_dirs:
        if not os.path.exists(src_dir):
            continue
            
        rust_files = find_rust_files(src_dir)
        
        for file_path in rust_files:
            if has_test_module(file_path):
                files_with_tests.append(file_path)
            else:
                files_needing_tests.append(file_path)
    
    print("Test Coverage Analysis")
    print("=" * 50)
    print(f"Files with tests: {len(files_with_tests)}")
    print(f"Files needing tests: {len(files_needing_tests)}")
    print()
    
    if files_needing_tests:
        print("Files that need test modules:")
        print("-" * 30)
        for file_path in files_needing_tests:
            print(f"  - {file_path}")
            functions = extract_functions(file_path)
            if functions:
                print(f"    Functions to test: {', '.join(functions[:5])}")
                if len(functions) > 5:
                    print(f"    ... and {len(functions) - 5} more")
        print()
    
    # Generate a test coverage report
    total_files = len(files_with_tests) + len(files_needing_tests)
    coverage_percentage = (len(files_with_tests) / total_files * 100) if total_files > 0 else 0
    
    print(f"Current test module coverage: {coverage_percentage:.1f}%")
    print(f"Files remaining to add tests: {len(files_needing_tests)}")

if __name__ == "__main__":
    main()