# Release Notes - v0.1.6

## CI/CD Enhancement Release

**Released**: June 2, 2025 12:17 AM

### 🛠️ CI/CD Improvements
- **Code Quality Enforcement**: Fixed all formatting and clippy warnings across the entire codebase
- **Format String Modernization**: Updated 23+ format! macros to use inline variable syntax
- **Test Reporting**: Fixed JUnit XML generation for proper Codecov integration
- **Pre-commit Guidelines**: Added documentation for local checks matching CI behavior exactly

### 🎯 Developer Experience
- **Consistent Formatting**: `cargo fmt --all -- --check` now matches CI formatting exactly
- **Clear Guidelines**: Pre-commit checks documented in CLAUDE.md for all contributors
- **Better Gitignore**: Fixed patterns to properly exclude build artifacts while including source

### 🐛 Bug Fixes
- Fixed tarpaulin JUnit output (removed unsupported --out junit flag)
- Resolved all clippy::uninlined_format_args warnings
- Fixed import ordering (std imports after external crates)
- Corrected multi-line format! and closure formatting
- Fixed benchmark source files caught by overly broad .gitignore

### 📚 Documentation Updates
- Updated all version references to v0.1.6
- Added CI/CD troubleshooting guide
- Archived completed testing documentation
- Updated memory banks with lessons learned

### 🏗️ Code Quality Stats
- **0** formatting issues
- **0** clippy warnings  
- **578** tests passing
- **95%** test coverage maintained

### 📦 Technical Details
- Simplified JUnit XML generation using static file approach
- Improved .gitignore precision (`/benchmarks/` not `benchmarks/`)
- Consolidated test framework continues to work flawlessly

This release focuses on developer experience and CI/CD reliability, ensuring contributors can work efficiently without CI failures.

**Full Changelog**: https://github.com/doublegate/Aura-DecentralTrust/compare/v0.1.5...v0.1.6