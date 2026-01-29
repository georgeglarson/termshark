# Termshark

A terminal user-interface for tshark, inspired by Wireshark.

If you're debugging on a remote machine with a large pcap and no desire to scp it back to your desktop, termshark can help!

> **Note:** This is a modernized fork of [gcla/termshark](https://github.com/gcla/termshark) with significant architectural improvements, updated dependencies, and enhanced test coverage.

## Features

- Read pcap files or sniff live interfaces (where tshark is permitted)
- Filter pcaps or live captures using Wireshark's display filters
- Reassemble and inspect TCP and UDP flows
- View network conversations by protocol
- Copy ranges of packets to the clipboard from the terminal
- Written in Go, compiles to a single executable on each platform

## Requirements

- **tshark** (part of Wireshark) version 1.10.2 or higher must be in your `PATH`
- Go 1.22 or higher (for building from source)

## Installation

### From Source

```bash
git clone https://github.com/georgeglarson/termshark.git
cd termshark
go build -o termshark ./cmd/termshark
```

Or install directly:

```bash
go install github.com/gcla/termshark/v2/cmd/termshark@latest
```

Then add `~/go/bin/` to your `PATH`.

## Quick Start

Inspect a local pcap:

```bash
termshark -r test.pcap
```

Capture ping packets on interface `eth0`:

```bash
termshark -i eth0 icmp
```

Run `termshark -h` for options.

## Documentation

- [User Guide](docs/UserGuide.md)
- [FAQ](docs/FAQ.md)
- [Changelog](CHANGELOG.md)

## Dependencies

Runtime:
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - command-line network protocol analyzer

Build-time (Go modules, fetched automatically):
- [tcell](https://github.com/gdamore/tcell) - terminal handling
- [gowid](https://github.com/gcla/gowid) - terminal UI widgets

## Fork Improvements

This fork includes substantial modernization:

- **Architecture**: Centralized goroutine lifecycle management, UIState struct for globals
- **Code Quality**: Reduced `cmain()` from 1260 to 574 lines, extracted 27+ helper functions
- **Modern Go**: Updated to Go 1.22+, uses `errors.Is/As`, `slices` package, range-over-int
- **Testing**: Improved coverage across core packages (lifecycle 100%, configs 39%, pcap 30%)
- **Dependencies**: Removed deprecated APIs, updated to current library versions

See [CODE_QUALITY_AUDIT.md](CODE_QUALITY_AUDIT.md) for details.

## Original Project

This is a fork of [termshark](https://github.com/gcla/termshark) by Graham Clark. The original project and its contributors are acknowledged in the [LICENSE](LICENSE) file.

## License

MIT License - see [LICENSE](LICENSE) for details.
