# Contributing to Aura

We love your input! We want to make contributing to Aura as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Build Prerequisites

Please ensure you have all required dependencies installed:

```bash
# Fedora/RHEL/Bazzite
sudo dnf install -y gcc gcc-c++ clang clang-devel rocksdb-devel libzstd-devel

# Ubuntu/Debian  
sudo apt-get install -y build-essential clang libclang-dev librocksdb-dev libzstd-dev
```

See README.md for complete build instructions.

## Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable.
2. Update the CHANGELOG.md with your changes following the existing format.
3. The PR will be merged once you have the sign-off of at least one maintainer.

## Any contributions you make will be under the MIT/Apache 2.0 Software License

When you submit code changes, your submissions are understood to be under the same [MIT/Apache 2.0 License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/doublegate/Aura-DecentralTrust/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/doublegate/Aura-DecentralTrust/issues/new).

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Code Style

- Use `cargo fmt` before committing
- Run `cargo clippy` and address any warnings
- Follow Rust naming conventions
- Write documentation for public APIs
- Add tests for new functionality

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

## Documentation

- Keep CLAUDE.md updated with any significant architectural decisions
- Update relevant .md files in the to-dos/ directory for planning changes
- Use inline documentation (///) for public APIs
- Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/) format

## License

By contributing, you agree that your contributions will be licensed under the project's MIT/Apache 2.0 License.