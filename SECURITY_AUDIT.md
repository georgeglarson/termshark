# Security Audit Report: Termshark

**Date:** 2026-01-27
**Project:** Termshark - Terminal UI for tshark
**Auditor:** Claude Opus 4.5

---

## Executive Summary

| Category | Status | Issues Found | Fixed |
|----------|--------|--------------|-------|
| Command Injection | Secure | 0 | N/A |
| File Operations | Fixed | 6 | 6 |
| Input Validation | Fixed | 5 | 5 |
| Dependencies | Fixed | 2 critical, 3 medium | 2 critical |

---

## 1. Command Injection - SECURE

The project correctly uses `exec.Command()` with array arguments throughout, preventing shell injection. User inputs (display filters, capture filters, file paths) are passed as separate command-line arguments, not through shell interpretation.

**Files reviewed:**
- `pkg/pcap/cmds.go` - tshark command construction
- `pkg/pcap/loader.go` - PCAP loading commands
- `widgets/filter/filter.go` - Filter validation
- `ui/searchbyfilter.go` - Search commands

---

## 2. File Operations

### 2.1 World-Writable Permissions - FIXED

Changed directory permissions from `0777` to `0700` and file permissions from `0666` to `0600`.

| File | Issue | Status |
|------|-------|--------|
| `configs/profiles/profiles.go` | Directory permissions | FIXED |
| `cmd/termshark/termshark.go` | Cache dir and log file permissions | FIXED |

**Commit:** `7cd4cca` - Fix insecure file permissions

### 2.2 TOCTOU Race Conditions - FIXED

Replaced `os.Stat()` + `os.Mkdir()` pattern with atomic `os.MkdirAll()`.

| File | Issue | Status |
|------|-------|--------|
| `configs/profiles/profiles.go` | Race in `CopyToAndUse()` and `Use()` | FIXED |
| `cmd/termshark/termshark.go` | Race in cache dir creation | FIXED |

**Commit:** `a552a97` - Fix TOCTOU race conditions in directory creation

### 2.3 Unvalidated CLI Profile Names - FIXED

Profile names from CLI `--profile` argument are now validated using `filenamify.Filenamify()`, matching the validation already used for UI-created profiles.

**Commit:** `ae5af27` - Validate --profile CLI argument to prevent path traversal

### 2.4 Temp File Cleanup - FIXED

Removed `&& false` condition that prevented temporary config files from being deleted.

**Commit:** `5ae8376` - Enable temp file cleanup for config viewer

---

## 3. Input Validation

### 3.1 Unchecked Array Bounds - FIXED

Added bounds checks before accessing `curPsml[0]`, `curPsml[1:]`, and `curCounts[1:]` to prevent panics when processing malformed XML data.

| File | Issue | Status |
|------|-------|--------|
| `pkg/pcap/loader.go` | Unchecked array access | FIXED |
| `ui/searchbyfilter.go` | Unchecked array access | FIXED |

**Commit:** `0ae54ae` - Fix unchecked array bounds in PSML parsing

### 3.2 Positive Findings

- No `unsafe` package usage
- Go's XML parser prevents XXE/billion laughs by default
- Most `strconv.Atoi` calls have error handling

---

## 4. Dependencies - FIXED

### 4.1 Critical Vulnerabilities - FIXED

| Package | Previous Version | CVE | Severity | Updated To |
|---------|------------------|-----|----------|------------|
| `sirupsen/logrus` | v1.7.0 | CVE-2025-65637 | HIGH (DoS) | v1.9.3 |
| `gin-gonic/gin` | v1.7.0 (indirect) | CVE-2020-28483 | MEDIUM | v1.7.0 (removed) |

**Commit:** `2da7b90` - Upgrade Go to 1.22 and update dependencies

### 4.2 Outdated/Unmaintained - NOTED

| Package | Last Update | Risk | Status |
|---------|-------------|------|--------|
| `shibukawa/configdir` | 2017 | No security updates for 8+ years | Low priority |
| `gcla/tail` | 2019 | Limited maintenance | Low priority |
| `kballard/go-shellquote` | 2018 | Stale | Low priority |

### 4.3 Go Version - FIXED

Previous: Go 1.13
Updated: Go 1.22

**Commit:** `2da7b90` - Upgrade Go to 1.22 and update dependencies

---

## Remaining Work

### High Priority
1. ~~Upgrade `sirupsen/logrus` to v1.9.3+~~ DONE
2. ~~Upgrade Go version in go.mod to 1.21+~~ DONE (upgraded to 1.22)
3. ~~Validate `--profile` CLI argument with `filenamify.Filenamify()`~~ DONE

### Medium Priority
4. ~~Review and update other outdated dependencies~~ DONE
5. Add symlink validation in profile enumeration

---

## Commits

| Commit | Description |
|--------|-------------|
| `0ae54ae` | Fix unchecked array bounds in PSML parsing |
| `7cd4cca` | Fix insecure file permissions |
| `5ae8376` | Enable temp file cleanup for config viewer |
| `a552a97` | Fix TOCTOU race conditions in directory creation |
| `2da7b90` | Upgrade Go to 1.22 and update dependencies |
| `ae5af27` | Validate --profile CLI argument to prevent path traversal |
