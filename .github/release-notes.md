## SysTrace v1.1.0

A fast, native Rust GUI forensic analysis tool for Sysmon logs — built for DFIR investigators.

### What's new in v1.1.0

- **Native EVTX parsing** — open `.evtx` files directly, no EVTXECmd required. Format auto-detected by magic bytes; pure Rust BinXml decoder with template caching and substitution resolution.

### Features

- **Native EVTX parsing** — open `.evtx` files directly, no external tools required; format auto-detected by magic bytes
- **Interactive process tree** — full parent/child hierarchy from Sysmon EventId 1, with color coding for injection targets, SYSTEM processes, terminated processes, and synthetic placeholders
- **9 telemetry tabs per process** — Overview, Network, Files, Registry, Pipes, Injection, Modules, Detection, Timeline
- **Cross-process timeline** — select multiple processes, generate a unified time-sorted event table
- **Forensic filters** — Integrity Level, User, Network Activity, Persistence Activity, and MITRE ATT&CK technique filters (AND-logic, badge count)
- **Detection tab** — surfaces EventIds 2, 4, 9, 16, 19–21, 24 color-coded by category
- **MITRE ATT&CK** — technique IDs parsed from RuleName, shown in every table and as a tree filter
- **Stats popup** — metric cards and bar charts for event types, integrity levels, users, and hosts
- **Process bookmarks** — attach investigation notes to any process node
- **Multi-host support** — host selector when the file spans multiple machines
- **Export** — CSV, JSON, and Graphviz DOT formats
- **Drag & drop** loading with live progress bar

### Getting Started

Drop a `.evtx` file or EVTXECmd NDJSON export onto the window, or pass it as a CLI argument:

```
systrace-gui Microsoft-Windows-Sysmon%4Operational.evtx
```

### Downloads

| Platform | File |
|---|---|
| Windows x86_64 | `systrace-windows-x86_64.exe` |
| Linux x86_64 | `systrace-linux-x86_64` |
| macOS Intel | `systrace-macos-x86_64` |
| macOS Apple Silicon | `systrace-macos-aarch64` |

> **Linux:** built on Ubuntu 22.04 (glibc 2.35). Requires X11 or Wayland and OpenGL. On headless servers, use Xvfb.
