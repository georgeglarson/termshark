# Maintainer Notes

## Building

```bash
go build -v ./cmd/termshark
```

## Testing

```bash
go test -v ./...
```

## Release Checklist

1. Update version in `CHANGELOG.md`
2. Run full test suite: `go test -race ./...`
3. Build for target platforms
4. Create GitHub release with binaries

## Original Package Maintainers

This is a fork. The original termshark project has package maintainers for various platforms (Arch, Homebrew, Snap, etc.). Those packages install the original gcla/termshark, not this fork.

If you'd like to package this fork for a platform, please open an issue.
