# Termshark Dependency Audit Report

**Date:** 2026-01-28
**Go Version:** 1.22

## Summary

| Dependency | Last Updated | Risk | Recommendation |
|------------|--------------|------|----------------|
| shibukawa/configdir | 2017 | Medium | ~~Replace with adrg/xdg or stdlib~~ **DONE** |
| kballard/go-shellquote | 2018 | Low | Keep (stable, no security issues) |
| gcla/tail | 2019 | Low | Keep (fork, maintainer controls) |
| condchan | 2019 | Medium | Replace with channels or sync.Cond |
| gopkg.in/tomb.v1 | 2014 | Low | Replace with errgroup or context |
| mitchellh/go-homedir | 2019 | Low | ~~Replace with os.UserHomeDir()~~ **DONE** |
| rakyll/statik | 2020 | Medium | ~~Replace with go:embed~~ **DONE** |
| tevino/abool | 2020 | Low | ~~Replace with sync/atomic.Bool~~ **DONE** |

---

## Detailed Analysis

### 1. shibukawa/configdir (2017)

**Status:** Unmaintained since 2017
**Risk:** Medium
**Used for:** XDG-compliant config directory resolution
**Used in:** configs/profiles/profiles.go, utils.go, cmd/termshark/termshark.go, ui/lastline.go, pkg/shark/wiresharkcfg/cfg.go, pkg/theme/utils.go

**Current alternatives:**
- **adrg/xdg** - Modern, actively maintained (1,125+ imports), full XDG spec
- **os.UserConfigDir()** / **os.UserCacheDir()** - Go 1.13+ stdlib (limited but sufficient)

**Recommendation:** Replace with `adrg/xdg` for full XDG compliance, or stdlib functions if only basic paths are needed. The stdlib functions are simpler but don't provide QueryFolders or full XDG precedence.

**Migration effort:** Medium - need to update path resolution code in configs/profiles/

---

### 2. kballard/go-shellquote (2018)

**Status:** Stable, no activity since 2018
**Risk:** Low
**Used for:** Shell quoting/unquoting for display filter commands

**Current alternatives:**
- **frioux/shellquote** - Fork with some updates

**Recommendation:** Keep for now. Shell quoting is a stable problem domain with no security vulnerabilities reported. The code is simple and correct.

**Migration effort:** N/A

---

### 3. gcla/tail (2019)

**Status:** Fork maintained by project author
**Risk:** Low
**Used for:** Tailing log files and tshark output

**Current alternatives:**
- **nxadm/tail** - Actively maintained fork of hpcloud/tail

**Recommendation:** Keep. This is the project maintainer's own fork with project-specific fixes. Switching to nxadm/tail would lose those customizations.

**Migration effort:** N/A

---

### 4. gitlab.com/jonas.jasas/condchan (2019)

**Status:** Unmaintained since 2019
**Risk:** Medium
**Used for:** Condition variable that works with select{}
**Used in:** ui/searchbyfilter.go

**Current alternatives:**
- **sync.Cond** - stdlib (but doesn't work with select)
- **Channels** - close() for broadcast, send for signal
- Custom implementation combining both

**Recommendation:** Replace with channel-based pattern. The main use case (broadcast + select) can be achieved by creating a new channel for each broadcast cycle.

**Migration effort:** Medium - need to identify all usages and refactor coordination logic

---

### 5. gopkg.in/tomb.v1 (2014)

**Status:** Inactive (no vulnerabilities)
**Risk:** Low
**Used for:** Goroutine lifecycle management (indirect via gcla/tail)

**Current alternatives:**
- **gopkg.in/tomb.v2** - Updated version with better API
- **golang.org/x/sync/errgroup** - stdlib-adjacent, context-aware
- **context.Context** - For cancellation only

**Recommendation:** This is an indirect dependency from gcla/tail. If tail is kept, tomb.v1 stays. If tail is replaced with nxadm/tail, tomb.v1 goes away naturally.

**Migration effort:** Low (indirect dependency)

---

### 6. mitchellh/go-homedir (2019)

**Status:** Superseded by stdlib
**Risk:** Low
**Used for:** Getting user home directory
**Used in:** pkg/shark/wiresharkcfg/cfg.go

**Current alternatives:**
- **os.UserHomeDir()** - Go 1.12+ stdlib (direct replacement)

**Recommendation:** Replace with stdlib. The only feature missing from stdlib is `Expand()` for `~` path expansion, which is trivial to implement.

**Migration effort:** Low - find/replace with stdlib call

---

### 7. rakyll/statik (2020)

**Status:** Superseded by go:embed
**Risk:** Medium
**Used for:** Embedding static assets (themes, etc.)
**Used in:** ui/lastline.go, pkg/theme/utils.go, assets/statik/statik.go

**Current alternatives:**
- **//go:embed** - Go 1.16+ stdlib directive

**Recommendation:** Replace with go:embed. This eliminates a build-time code generation step and simplifies the build process. Many projects have successfully migrated.

**Migration effort:** Medium - need to:
1. Remove statik code generation
2. Add embed directives to asset directories
3. Update asset loading code to use embed.FS

---

### 8. tevino/abool (2020)

**Status:** Superseded by stdlib
**Risk:** Low
**Used for:** Atomic boolean operations
**Used in:** utils.go

**Current alternatives:**
- **sync/atomic.Bool** - Go 1.19+ stdlib

**Recommendation:** Replace with stdlib. The project uses Go 1.22, so atomic.Bool is available. Note: tevino/abool has convenience methods like `Toggle()` and `SetToIf()` not in stdlib, but these are trivial to implement.

**Migration effort:** Low - update to use atomic.Bool

---

## Priority Recommendations

### Immediate (Low effort, high benefit) - COMPLETED
1. ~~**mitchellh/go-homedir** → os.UserHomeDir()~~ **DONE**
2. ~~**tevino/abool** → sync/atomic.Bool~~ **DONE**

### Short-term (Medium effort) - COMPLETED
3. ~~**rakyll/statik** → go:embed~~ **DONE**
4. ~~**shibukawa/configdir** → adrg/xdg~~ **DONE**

### Evaluate Later
5. **condchan** → channels (needs usage analysis)
6. **kballard/go-shellquote** → keep
7. **gcla/tail** → keep
8. **tomb.v1** → keep (indirect)

---

## Security Notes

- No known CVEs in any of the audited dependencies
- All dependencies are read from pkg.go.dev checksum database
- Shell quoting library is security-sensitive but appears correct

---

## References

- [adrg/xdg](https://github.com/adrg/xdg) - XDG Base Directory Specification
- [nxadm/tail](https://github.com/nxadm/tail) - File tailing library
- [sync.Cond vs Channels](https://victoriametrics.com/blog/go-sync-cond/)
- [go:embed migration](https://github.com/rakyll/statik/issues/123)
- [os.UserHomeDir proposal](https://github.com/golang/go/issues/26463)
