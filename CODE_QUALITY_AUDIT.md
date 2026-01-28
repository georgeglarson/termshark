# Code Quality Audit Report: Termshark

**Date:** 2026-01-27
**Project:** Termshark - Terminal UI for tshark
**Auditor:** Claude Opus 4.5

---

## Executive Summary

| Category | Status | Issues Found | Fixed |
|----------|--------|--------------|-------|
| Deprecated APIs | Partial | 6 files with ioutil | 6 |
| Error Handling | Pending | pkg/errors usage, inconsistent patterns | 0 |
| Goroutine Lifecycle | In Progress | Global WaitGroup injection | ~40 |
| Test Coverage | Pending | ~30% coverage, 0% for UI | 0 |
| Code Complexity | Pending | 1260-line cmain(), 80+ UI globals | 0 |
| Dependencies | Pending | Outdated fsnotify path | 0 |

**Overall Assessment:** Good architecture with modernization opportunities

---

## 1. Deprecated APIs - PARTIAL

### 1.1 io/ioutil Usage (Deprecated since Go 1.16) - FIXED

All `io/ioutil` usages replaced with modern equivalents:
- `ioutil.ReadAll` -> `io.ReadAll`
- `ioutil.ReadDir` -> `os.ReadDir`
- `ioutil.ReadFile` -> `os.ReadFile`
- `ioutil.WriteFile` -> `os.WriteFile`
- `ioutil.TempFile` -> `os.CreateTemp`
- `ioutil.Discard` -> `io.Discard`

**Commit:** `5aacbe6` - Replace deprecated io/ioutil with modern equivalents

### 1.2 Deprecated Import Paths - PARTIAL

| Current | Replacement | Status |
|---------|-------------|--------|
| `gopkg.in/fsnotify/fsnotify.v1` | `github.com/fsnotify/fsnotify` | FIXED |
| `gopkg.in/tomb.v1` | Consider removal or update | Pending |

**Commit:** `53277dd` - Update fsnotify import to modern path

---

## 2. Error Handling - PARTIAL

### 2.1 pkg/errors Library (Deprecated) - FIXED

Removed all direct usage of `github.com/pkg/errors`. All `errors.WithStack()` calls replaced with direct error returns.

Note: `pkg/errors` remains as an indirect dependency via `gowid`.

**Commit:** `92cb2a9` - Remove direct usage of deprecated github.com/pkg/errors

### 2.2 Inconsistent Error Patterns

- Type assertions for errors (`*exec.ExitError`) instead of `errors.As()`
- No use of `errors.Is()` or `errors.As()` found
- Some functions panic, others return errors

---

## 3. Goroutine Lifecycle - IN PROGRESS

### 3.1 Global WaitGroup Injection (Anti-pattern) - FOUNDATION LAID

**Original pattern:** `cmd/termshark/termshark.go:57-69`

**Solution:** Created `pkg/lifecycle.Tracker` that provides:
- Centralized goroutine tracking via WaitGroup
- Context-based shutdown signaling
- `Go()` and `GoWithContext()` methods for modern pattern
- `WaitGroup()` for backward compatibility

**Current state:**
- `lifecycle.Tracker` created and tested
- `main()` uses Tracker, provides WaitGroup to legacy code
- All `TrackedGo()` calls migrated to `termshark.Go()` across:
  - `ui/` (13 calls)
  - `pkg/confwatcher/` (2 calls)
  - `pkg/summary/` (1 call)
  - `pkg/capinfo/` (3 calls)
  - `pkg/convs/` (3 calls)
  - `pkg/streams/` (4 calls)
  - `widgets/filter/` (2 calls)
  - `widgets/wormhole/` (2 calls)
  - `pkg/pcap/` (11 calls + 1 in test)

**Context awareness added to goroutines:**
- `pkg/confwatcher/confwatcher.go` - file watcher loop
- `ui/capinfoui.go` - spinner ticker
- `ui/convscallbacks.go` - spinner ticker
- `ui/searchalg.go` - search progress loop
- `ui/streamui.go` - stream chunks ticker
- `ui/switchterm.go` - term dialog countdown
- `utils.go` - `RunOnDoubleTicker()` helper
- `widgets/filter/filter.go` - filter validation loops

**Remaining work:**
- Consider deprecating `TrackedGo()` function (replaced by `termshark.Go()`)

**Commits:**
- `f4cceb5` - Add lifecycle package for centralized goroutine management
- `e028f99` - Migrate TrackedGo calls to termshark.Go()
- `7a71c2b` - Remove unused Goroutinewg package variables
- `b4346aa` - Add context awareness to goroutines for graceful shutdown

---

## 4. Test Coverage - PENDING

### 4.1 Current State

| Area | Coverage | Notes |
|------|----------|-------|
| Widgets (hexdumper, number, etc.) | Good | Unit tests exist |
| Parsers (wiresharkcfg, streams) | Good | Extensive test data |
| UI orchestration (`ui/ui.go`) | None | 4412 LOC, 0 tests |
| Main logic (`cmd/termshark/`) | None | Not testable (globals) |
| Configuration (`configs/`) | None | Should have tests |
| Loaders (`pkg/pcap/loader.go`) | Limited | 2359 LOC, minimal tests |

**Estimated overall coverage:** ~30%

### 4.2 Test Quality Issues

- `pkg/streams/loader_test.go:1133`: Uses `context.TODO()` (should be `context.Background()`)
- No mocks for tshark commands
- Integration-style tests rather than unit tests

---

## 5. Code Complexity - PENDING

### 5.1 Long Functions

| Function | File | Lines | Recommendation |
|----------|------|-------|----------------|
| `cmain()` | `cmd/termshark/termshark.go:112-1372` | 1260 | Extract signal handling, profile logic |
| UI initialization | `ui/ui.go` | 4412 total | Extract into components |

### 5.2 Global State in UI

**Location:** `ui/ui.go:93-150+`

80+ package-level variables:
```go
var appViewNoKeys *holder.Widget
var appView *holder.Widget
var packetListViewHolder *holder.Widget
// ... many more
```

**Problems:**
- Hard to test
- Hard to reason about state
- Limits reusability

**Recommendation:** Create `AppState` struct, use dependency injection

### 5.3 Type Safety

| Location | Issue | Recommendation |
|----------|-------|----------------|
| `pkg/pcap/loader.go:121` | `interface{}` for callbacks | Use generics |
| `pkg/pcap/handlers.go:52` | `type HandlerList []interface{}` | Use `HandlerList[T any]` |

---

## 6. Dependencies - PENDING

### 6.1 Outdated/Problematic

| Package | Issue | Action |
|---------|-------|--------|
| `github.com/pkg/errors` | Deprecated | Remove, use stdlib |
| `gopkg.in/fsnotify/fsnotify.v1` | Old import path | Update to `github.com/fsnotify/fsnotify` |
| `gopkg.in/tomb.v1` | Last updated 2014 | Evaluate removal |
| `github.com/gcla/tail` | Fork from 2019 | Evaluate alternatives |

### 6.2 Unused Imports

| File | Import | Issue |
|------|--------|-------|
| `cmd/termshark/termshark.go:47` | `_ "net/http"` | Unused |

---

## 7. Modernization Opportunities

### 7.1 Go 1.22+ Features

| Feature | Current Pattern | Modern Pattern |
|---------|-----------------|----------------|
| Range over integers | `for i := 0; i < len(s); i++` | `for i := range len(s)` |
| Error wrapping | `pkg/errors.WithStack()` | `fmt.Errorf("%w", err)` |

### 7.2 Generics (Go 1.18+)

Replace `interface{}` with typed generics:
```go
// Before
type HandlerList []interface{}

// After
type HandlerList[T any] []T
```

---

## Remaining Work

### Phase 1: Quick Wins (Immediate) - COMPLETE
1. ~~Replace `io/ioutil` with modern equivalents~~ DONE
2. ~~Update `gopkg.in/fsnotify/fsnotify.v1` import path~~ DONE
3. ~~Remove unused imports~~ DONE
4. ~~Add golangci-lint configuration~~ DONE

### Phase 2: Error Handling (Short Term)
5. ~~Remove `github.com/pkg/errors` dependency~~ DONE (direct usage removed)
6. ~~Migrate to stdlib error wrapping~~ DONE
7. Add `errors.Is()`/`errors.As()` where appropriate

### Phase 3: Architecture (Medium Term) - IN PROGRESS
8. ~~Refactor goroutine lifecycle to use context/errgroup~~ COMPLETE
   - ~~Create lifecycle.Tracker~~ DONE
   - ~~Migrate all TrackedGo() calls to termshark.Go()~~ DONE
   - ~~Remove package-level Goroutinewg variables~~ DONE
   - ~~Add context awareness to long-running goroutines~~ DONE
9. Extract `cmain()` into smaller functions
10. Create `AppState` struct for UI globals

### Phase 4: Testing (Medium Term)
11. Add tests for configuration loading
12. Add tests for loader state machine
13. Add integration tests with mock tshark

### Phase 5: Type Safety (Long Term)
14. Replace `interface{}` callbacks with generics
15. Improve type safety in handler lists

---

## Commits

| Commit | Description |
|--------|-------------|
| `5aacbe6` | Replace deprecated io/ioutil with modern equivalents |
| `53277dd` | Update fsnotify import to modern path |
| `7e3fcf5` | Remove redundant blank import of net/http |
| `950e8ad` | Add golangci-lint configuration |
| `92cb2a9` | Remove direct usage of deprecated github.com/pkg/errors |
| `f4cceb5` | Add lifecycle package for centralized goroutine management |

---

## Quality Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Test Coverage | ~30% | 50%+ |
| Deprecated API Usage | 0 files | 0 |
| Long Functions (>500 LOC) | 7 | 0 |
| Package Globals (UI) | 80+ | <20 |
| golangci-lint Config | Added | Passing |
