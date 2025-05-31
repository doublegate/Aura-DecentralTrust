#!/bin/bash
# Check CI status and common issues

echo "=== Checking CI Status ==="
echo

# Check if gh CLI is available
if command -v gh &> /dev/null; then
    echo "Using GitHub CLI to check workflow status..."
    gh run list --workflow=ci.yml --limit=5
    echo
    echo "Latest run details:"
    gh run view --log-failed
else
    echo "GitHub CLI (gh) not found. Install it for better CI monitoring:"
    echo "  https://cli.github.com/"
fi

echo
echo "=== Checking for Common CI Issues Locally ==="
echo

# Check for any remaining clippy warnings
echo "1. Checking for clippy warnings..."
if cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -E "^error:|^warning:" > /tmp/clippy_issues.txt; then
    if [ -s /tmp/clippy_issues.txt ]; then
        echo "❌ Found clippy issues:"
        cat /tmp/clippy_issues.txt | head -20
        echo
        echo "Full output saved to /tmp/clippy_issues.txt"
    else
        echo "✅ No clippy warnings found"
    fi
else
    echo "✅ Clippy check passed"
fi

echo
echo "2. Checking if all tests compile..."
if cargo test --no-run 2>&1 | grep -E "^error:" > /tmp/test_compile_issues.txt; then
    if [ -s /tmp/test_compile_issues.txt ]; then
        echo "❌ Test compilation errors:"
        cat /tmp/test_compile_issues.txt | head -10
    fi
else
    echo "✅ All tests compile"
fi

echo
echo "3. Checking for formatting issues..."
if ! cargo fmt --all -- --check &> /dev/null; then
    echo "❌ Formatting issues found. Run 'cargo fmt' to fix."
else
    echo "✅ Code formatting is correct"
fi

echo
echo "=== Direct CI Link ==="
echo "Check your CI runs at:"
echo "https://github.com/doublegate/Aura-DecentralTrust/actions/workflows/ci.yml"
echo
echo "If CI hasn't triggered:"
echo "1. Check if workflows are enabled in your repo settings"
echo "2. Try pushing an empty commit: git commit --allow-empty -m 'Trigger CI'"