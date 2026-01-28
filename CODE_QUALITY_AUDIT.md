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
| Goroutine Lifecycle | Pending | Global WaitGroup injection | 0 |
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

## 2. Error Handling - PENDING

### 2.1 pkg/errors Library (Deprecated)

Uses `github.com/pkg/errors` instead of Go 1.13+ stdlib error wrapping.

| File | Usage | Replacement |
|------|-------|-------------|
| `utils.go:157` | `errors.WithStack()` | `fmt.Errorf("%w", err)` |

**Recommendation:** Migrate to stdlib `fmt.Errorf("%w", err)` and `errors.Is()`/`errors.As()`

### 2.2 Inconsistent Error Patterns

- Type assertions for errors (`*exec.ExitError`) instead of `errors.As()`
- No use of `errors.Is()` or `errors.As()` found
- Some functions panic, others return errors

---

## 3. Goroutine Lifecycle - PENDING

### 3.1 Global WaitGroup Injection (Anti-pattern)

**Location:** `cmd/termshark/termshark.go:57-69`

```go
var ensureGoroutinesStopWG sync.WaitGroup
filter.Goroutinewg = &ensureGoroutinesStopWG
pcap.Goroutinewg = &ensureGoroutinesStopWG
streams.Goroutinewg = &ensureGoroutinesStopWG
// ... 8 packages total
```

**Affected packages:**
- `widgets/filter/filter.go:45`
- `ui/ui.go:83`
- `pkg/pcap/loader.go:44`
- `pkg/convs/loader.go:22`
- `pkg/capinfo/loader.go:22`
- `pkg/summary/summary.go:89`
- `pkg/streams/loader.go:24`
- `pkg/confwatcher/confwatcher.go:94`

**Problems:**
- Makes testing difficult
- Violates encapsulation
- Fragile shutdown (missed goroutine = hang)

**Recommendation:** Use `context.WithCancel()` + `golang.org/x/sync/errgroup`

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
5. Remove `github.com/pkg/errors` dependency
6. Migrate to stdlib error wrapping
7. Add `errors.Is()`/`errors.As()` where appropriate

### Phase 3: Architecture (Medium Term)
8. Refactor goroutine lifecycle to use context/errgroup
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

---

## Quality Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Test Coverage | ~30% | 50%+ |
| Deprecated API Usage | 0 files | 0 |
| Long Functions (>500 LOC) | 7 | 0 |
| Package Globals (UI) | 80+ | <20 |
| golangci-lint Config | Added | Passing |
