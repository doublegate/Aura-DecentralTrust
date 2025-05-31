#!/bin/bash
# Generate code coverage report for Aura DecentralTrust

set -e

echo "Generating Code Coverage Report for Aura DecentralTrust"
echo "======================================================"
echo ""

# Check if cargo-tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
fi

# Clean previous coverage data
echo "Cleaning previous coverage data..."
rm -f cobertura.xml lcov.info tarpaulin-report.html

# Run coverage with tarpaulin
echo "Running tests with coverage..."
echo ""

# Generate coverage in multiple formats
cargo tarpaulin \
    --all-features \
    --workspace \
    --timeout 300 \
    --out Xml \
    --out Lcov \
    --out Html \
    --output-dir . \
    --exclude-files "*/tests/*" \
    --exclude-files "*/examples/*" \
    --exclude-files "*/target/*" \
    --exclude-files "*/build.rs" \
    --ignore-panics \
    --verbose

echo ""
echo "Coverage report generated!"
echo ""
echo "Output files:"
echo "  - cobertura.xml (for CI/CD tools)"
echo "  - lcov.info (for IDE extensions)"
echo "  - tarpaulin-report.html (for viewing in browser)"
echo ""

# Display summary
if [ -f "tarpaulin-report.html" ]; then
    echo "To view the HTML report, open:"
    echo "  file://$(pwd)/tarpaulin-report.html"
fi

# Check if we achieved our target
echo ""
echo "Checking coverage percentage..."
coverage_percent=$(grep -o 'line-rate="[0-9.]*"' cobertura.xml | head -1 | grep -o '[0-9.]*' || echo "0")
coverage_int=$(echo "$coverage_percent * 100" | bc | cut -d. -f1)

echo "Current coverage: ${coverage_int}%"

if [ "$coverage_int" -ge 90 ]; then
    echo "✓ Excellent! Coverage is above 90%"
elif [ "$coverage_int" -ge 80 ]; then
    echo "✓ Good! Coverage is above 80%"
elif [ "$coverage_int" -ge 70 ]; then
    echo "⚠ Coverage is above 70% but could be improved"
else
    echo "✗ Coverage is below 70% - more tests needed!"
fi

echo ""
echo "To improve coverage:"
echo "1. Look for uncovered lines in tarpaulin-report.html"
echo "2. Add tests for edge cases and error conditions"
echo "3. Test all public API functions"
echo "4. Add integration tests for complex workflows"