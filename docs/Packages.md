# Package Installation

> **Note:** This is a fork of termshark. The packages listed below install the original version from [gcla/termshark](https://github.com/gcla/termshark), not this fork.

## Installing This Fork

### From Source (Recommended)

```bash
git clone https://github.com/georgeglarson/termshark.git
cd termshark
go build -o termshark ./cmd/termshark
sudo mv termshark /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/gcla/termshark/v2/cmd/termshark@latest
```

Note: The module path remains `github.com/gcla/termshark/v2` for import compatibility.

---

## Original Package Sources

The following package sources install the **original gcla/termshark**, not this fork:

### Arch Linux

- [termshark](https://archlinux.org/packages/community/x86_64/termshark/): Official package
- [termshark-git](https://aur.archlinux.org/packages/termshark-git): AUR package

### Debian / Ubuntu / Kali

```bash
apt update
apt install termshark
```

### FreeBSD

```bash
pkg install termshark
```

### Homebrew (macOS)

```bash
brew install termshark
```

### MacPorts

```bash
sudo port install termshark
```

### NixOS

```bash
nix-env -iA nixpkgs.termshark
```

### Snap

```bash
snap install termshark
```

### Termux (Android)

```bash
pkg install root-repo
pkg install termshark
```
