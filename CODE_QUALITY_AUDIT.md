# Code Quality Audit Report: Termshark

**Date:** 2026-01-27
**Project:** Termshark - Terminal UI for tshark
**Auditor:** Claude Opus 4.5

---

## Executive Summary

| Category | Status | Issues Found | Fixed |
|----------|--------|--------------|-------|
| Deprecated APIs | COMPLETE | 6 files with ioutil, fsnotify path | All |
| Error Handling | COMPLETE | pkg/errors, %v wrapping, type assertions | All |
| Goroutine Lifecycle | COMPLETE | Global WaitGroup injection | ~40 goroutines |
| Code Complexity | PARTIAL | 1260-line cmain(), 80+ UI globals | ~145 lines extracted |
| Modernization | COMPLETE | strings.Replace, error wrapping, slices pkg, sort -> slices | All |
| Bug Fixes | COMPLETE | iota misuse (8 files), WriteGob error handling, redundant code | All |
| Test Coverage | Pending | ~30% coverage, 0% for UI | 0 |
| Type Safety | Pending | interface{} callbacks | 0 |

**Overall Assessment:** Significant modernization and bug fixes completed; testing and type safety remain

---

## 1. Deprecated APIs - COMPLETE

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

## 2. Error Handling - COMPLETE

### 2.1 pkg/errors Library (Deprecated) - FIXED

Removed all direct usage of `github.com/pkg/errors`. All `errors.WithStack()` calls replaced with direct error returns.

Note: `pkg/errors` remains as an indirect dependency via `gowid`.

**Commit:** `92cb2a9` - Remove direct usage of deprecated github.com/pkg/errors

### 2.2 Inconsistent Error Patterns - FIXED

- ~~Type assertions for errors (`*exec.ExitError`) instead of `errors.As()`~~ FIXED
- ~~No use of `errors.Is()` or `errors.As()` found~~ FIXED (11 type assertions migrated)
- ~~`fmt.Errorf` with `%v` instead of `%w` for error wrapping~~ FIXED
- Some functions panic, others return errors (acceptable pattern)

---

## 3. Goroutine Lifecycle - COMPLETE

### 3.1 Global WaitGroup Injection (Anti-pattern) - FIXED

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

- ~~`pkg/streams/loader_test.go:1133`: Uses `context.TODO()` (should be `context.Background()`)~~ FIXED
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

| Feature | Current Pattern | Modern Pattern | Status |
|---------|-----------------|----------------|--------|
| Range over integers | `for i := 0; i < len(s); i++` | `for i := range len(s)` | PARTIAL |
| Error wrapping | `pkg/errors.WithStack()` | `fmt.Errorf("%w", err)` | DONE |
| strings.Replace | `strings.Replace(s, o, n, -1)` | `strings.ReplaceAll(s, o, n)` | DONE |
| slices.Contains | Custom `StringInSlice()` | `slices.Contains()` | DONE |
| slices.Equal | `reflect.DeepEqual` for slices | `slices.Equal()` | DONE |
| sort.Strings | `sort.Strings(s)` | `slices.Sort(s)` | DONE |
| sort.Slice | `sort.Slice(s, less)` | `slices.SortFunc(s, cmp)` | DONE |
| slices.Insert | `append(s[:i], append([]T{v}, s[i:]...)...)` | `slices.Insert(s, i, v)` | DONE |
| slices.Delete | `append(s[:i], s[i+1:]...)` | `slices.Delete(s, i, i+1)` | DONE |
| clear() | `for k := range m { delete(m, k) }` | `clear(m)` | DONE |
| min/max builtins | `math.Min/Max` for numeric types | `min()/max()` | DONE |

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

### Phase 2: Error Handling (Short Term) - COMPLETE
5. ~~Remove `github.com/pkg/errors` dependency~~ DONE (direct usage removed)
6. ~~Migrate to stdlib error wrapping~~ DONE
   - All `fmt.Errorf` with `%v` for errors migrated to `%w`
   - Files updated: pkg/pcap/loader.go, pkg/streams/loader.go, pkg/convs/loader.go,
     pkg/capinfo/loader.go, pkg/theme/utils.go, pkg/system/picker_android.go,
     configs/profiles/profiles.go, ui/ui.go, ui/searchbyfilter.go
7. ~~Add `errors.Is()`/`errors.As()` where appropriate~~ DONE
   - 5 `io.EOF` comparisons migrated to `errors.Is()`
   - 11 `*exec.ExitError` and `*exec.Error` type assertions migrated to `errors.As()`

### Phase 3: Architecture (Medium Term) - IN PROGRESS
8. ~~Refactor goroutine lifecycle to use context/errgroup~~ COMPLETE
   - ~~Create lifecycle.Tracker~~ DONE
   - ~~Migrate all TrackedGo() calls to termshark.Go()~~ DONE
   - ~~Remove package-level Goroutinewg variables~~ DONE
   - ~~Add context awareness to long-running goroutines~~ DONE
9. Extract `cmain()` into smaller functions - IN PROGRESS
   - ~~Extract setupConfigDirs()~~ DONE
   - ~~Extract setupLogging()~~ DONE
   - ~~Extract validateTsharkBinary()~~ DONE
   - ~~Extract checkTsharkColorSupport()~~ DONE
   - ~~Extract createCacheDirs()~~ DONE
   - ~~Extract validateTTY()~~ DONE
   - ~~Extract applyTermOverride()~~ DONE
   - ~~Extract initUIState()~~ DONE
   - ~~Extract loadTsharkArgs()~~ DONE
   - ~~Extract loadCacheSettings()~~ DONE
   - ~~Extract configureBase16Colors()~~ DONE
   - Current cmain() size: ~1115 lines (down from ~1260, -145 lines)
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
| `e028f99` | Migrate TrackedGo calls to termshark.Go |
| `7a71c2b` | Remove unused Goroutinewg package variables |
| `b4346aa` | Add context awareness to goroutines for graceful shutdown |
| `1408e84` | Extract helper functions from cmain() |
| `b27d79e` | Extract TTY validation and TERM override functions |
| `74bdd17` | Extract UI state and config loading functions |
| `b1bcaf3` | Extract configureBase16Colors() |
| `f02aa90` | Use errors.Is() for io.EOF comparisons |
| `7438996` | Use errors.As() for exec.ExitError type assertions |
| `8dde9b6` | Modernize error wrapping (%w) and strings.ReplaceAll() |
| `eab3250` | Use Go 1.21+ slices package (slices.Contains, slices.Equal) |
| `a8188ec` | Fix iota bug in FieldType constants |
| `5d7f362` | Fix iota bugs in multiple const blocks (7 files) |

---

## Quality Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Test Coverage | ~30% | 50%+ |
| Deprecated API Usage | 0 files | 0 |
| Long Functions (>500 LOC) | 7 | 0 |
| Package Globals (UI) | 80+ | <20 |
| golangci-lint Config | Added | Passing |
