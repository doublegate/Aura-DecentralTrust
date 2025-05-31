# Release Process Guide

This guide explains the different approaches for automating release notes in the Aura DecentralTrust project.

## Current Problem

The original `release.yml` workflow has hard-coded release notes, which means every release would have identical notes. This guide presents better solutions.

## Recommended Approaches

### 1. GitHub Auto-Generated Release Notes (Simplest)

**File**: `.github/workflows/release-auto-notes.yml`

This approach uses GitHub's built-in release notes generator that:
- Automatically lists all merged PRs since the last release
- Groups contributors
- Shows commit history
- Links to the full changelog

**Pros**:
- Zero maintenance
- Always up-to-date
- Shows contributor credits
- Works out of the box

**Cons**:
- Less control over formatting
- Requires good PR titles and descriptions

**Usage**:
```bash
git tag v0.2.0
git push origin v0.2.0
```

### 2. Extract from CHANGELOG.md (Most Control)

**File**: `.github/workflows/release-changelog.yml`

This approach:
- Reads your CHANGELOG.md file
- Extracts the section for the current version
- Uses that as the release notes

**Pros**:
- Full control over content
- Follows Keep a Changelog format
- Can include detailed explanations
- Professional appearance

**Cons**:
- Requires updating CHANGELOG.md before each release
- Manual process

**Usage**:
1. Update CHANGELOG.md with the new version section
2. Commit the changes
3. Create and push the tag:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

### 3. Release Drafter (Best of Both Worlds)

**Files**: 
- `.github/release-drafter.yml` (configuration)
- `.github/workflows/release-drafter.yml` (workflow)

This approach:
- Automatically drafts releases as PRs are merged
- Categorizes changes based on labels
- Maintains a draft release that updates continuously
- You just need to publish when ready

**Pros**:
- Automated but customizable
- Groups changes by type
- Calculates next version automatically
- Shows contributors
- Always ready to release

**Cons**:
- Requires labeling PRs
- Needs initial setup

**Usage**:
1. Label your PRs with: `feature`, `bug`, `security`, `docs`, etc.
2. Release Drafter creates/updates a draft release automatically
3. When ready to release:
   - Go to GitHub Releases
   - Edit the draft
   - Add any manual notes
   - Publish

### 4. Custom Release Notes File

You could also create a `RELEASE_NOTES.md` file for each release:

```yaml
- name: Read Release Notes
  id: notes
  run: |
    if [ -f "RELEASE_NOTES.md" ]; then
      echo "NOTES<<EOF" >> $GITHUB_OUTPUT
      cat RELEASE_NOTES.md >> $GITHUB_OUTPUT
      echo "EOF" >> $GITHUB_OUTPUT
    else
      echo "NOTES=No release notes found" >> $GITHUB_OUTPUT
    fi
```

## Recommendation

For the Aura project, I recommend:

1. **Immediate**: Switch to `release-auto-notes.yml` for automatic release notes
2. **Long-term**: Implement Release Drafter for better organization
3. **Always**: Keep CHANGELOG.md updated for historical reference

## Switching Workflows

To switch from the current hard-coded approach:

```bash
# Option 1: Replace the existing workflow
mv .github/workflows/release-auto-notes.yml .github/workflows/release.yml

# Option 2: Keep multiple workflows and disable the old one
# Just rename release.yml to release.yml.old

# Option 3: Update the existing workflow in place
# Copy the content from one of the examples
```

## Example Release Notes

### Auto-Generated (GitHub)
```
## What's Changed
* Fix build errors and reorganize documentation by @doublegate in #1
* Implement critical security fixes for Phase 1 by @doublegate in #2
* Add comprehensive test coverage by @doublegate in #3

**Full Changelog**: https://github.com/doublegate/Aura-DecentralTrust/compare/v0.1.0...v0.2.0
```

### From CHANGELOG.md
```
## [0.2.0] - 2025-06-15

### Added
- API-blockchain integration
- Real DID resolution from ledger
- Transaction broadcasting

### Fixed
- Memory leak in P2P handler
- Race condition in consensus

### Security
- Added rate limiting to all endpoints
```

### Release Drafter
```
## 🚀 Features
- Add API-blockchain integration @doublegate (#4)
- Implement real DID resolution @doublegate (#5)

## 🐛 Bug Fixes
- Fix memory leak in P2P handler @doublegate (#6)
- Resolve race condition in consensus @doublegate (#7)

## 🔒 Security
- Add rate limiting to all endpoints @doublegate (#8)
```

## Best Practices

1. **Semantic Versioning**: Follow MAJOR.MINOR.PATCH
2. **Regular Releases**: Don't let changes accumulate too long
3. **Clear Descriptions**: Write good PR titles and descriptions
4. **Label PRs**: Use labels for better categorization
5. **Test Before Tagging**: Ensure CI passes before creating tags
6. **Draft First**: Consider creating draft releases for review
7. **Include Migration Guides**: For breaking changes
8. **Credit Contributors**: Acknowledge all contributors

## Versioning Strategy

- **Major** (1.0.0): Breaking changes, major features
- **Minor** (0.1.0): New features, backwards compatible
- **Patch** (0.0.1): Bug fixes, small improvements

## Release Checklist

- [ ] All tests passing
- [ ] CHANGELOG.md updated
- [ ] Version bumped in Cargo.toml files
- [ ] Documentation updated
- [ ] Security audit passing
- [ ] Create tag with `v` prefix
- [ ] Push tag to trigger release
- [ ] Verify binaries built correctly
- [ ] Announce release (Discord, Twitter, etc.)