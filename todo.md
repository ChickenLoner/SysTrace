# TODO: Add CSV Import Support for EvtxECmd Output

## Context
SysTrace supports raw EVTX and NDJSON import. Add EvtxECmd CSV output import.
CSV must produce identical results to `.claude/sysmon2.json` and raw EVTX file.
Reference CSV: `.claude/sysmon2.csv` (3,759 records).

## Key Differences: CSV vs JSON
- `TimeCreated`: CSV `2023-05-03 11:15:12.2335395` (no T, no tz) → normalize to `2023-05-03T11:15:12.2335395+00:00`
- `Payload`: same JSON, but CSV uses doubled-quote escaping (`""` → `"`)
- Extra CSV columns (Level, Provider, Channel, etc.) — ignored
- CSV has header row

## Tasks

### 1. Add `csv` crate dependency
- **File:** `crates/systrace-core/Cargo.toml`
- Add `csv = "1"` to `[dependencies]`

### 2. Add `parse_csv_file()` function
- **File:** `crates/systrace-core/src/parser.rs`
- Same signature as `parse_file()`
- Open with `csv::ReaderBuilder::new().has_headers(true).flexible(true)`
- Build column index map for: `RecordNumber`, `EventId`, `TimeCreated`, `Payload`, `Computer`, `UserName`, `MapDescription`, `ExecutableInfo`, `PayloadData1`–`PayloadData6`
- For each row: extract fields → construct `RawEvtxRecord` → normalize timestamp → `parse_payload()` → `extract_event()` → batch (500) and send
- Skip malformed rows, push `ParseError`

### 3. Update `parse_file_auto()` for CSV detection
- **File:** `crates/systrace-core/src/parser.rs`
- After EVTX magic check fails: read first line
- Starts with `{` → NDJSON (`parse_file()`)
- Contains `RecordNumber` + commas → CSV (`parse_csv_file()`)
- Else → fall back to NDJSON

### 4. Export from lib.rs
- **File:** `crates/systrace-core/src/lib.rs`
- Add `parse_csv_file` to `pub use parser::{...}`

### 5. Update file dialog filter
- **File:** `crates/systrace-gui/src/app.rs`
- Change `&["evtx", "json", "ndjson"]` → `&["evtx", "json", "ndjson", "csv"]`

### 6. Add integration test
- **File:** `crates/systrace-core/src/parser.rs` (tests module)
- Parse `.claude/sysmon2.csv` → verify 3759 records
- Compare event count and ProcessGuid set against `.claude/sysmon2.json`

## Files to Modify
1. `crates/systrace-core/Cargo.toml`
2. `crates/systrace-core/src/parser.rs`
3. `crates/systrace-core/src/lib.rs`
4. `crates/systrace-gui/src/app.rs`

## Verification
1. `cargo test -p systrace-core` — all tests pass
2. `cargo build --release` — clean build
3. Manual: load `.claude/sysmon2.csv` in app → same tree/counts as `.claude/sysmon2.json`
