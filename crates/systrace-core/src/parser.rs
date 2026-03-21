use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;

use crate::event::{EventDetail, SysmonEvent, SysmonEventType};
use crate::types::{parse_guid_opt, parse_mitre_rule_name, ParseError, ProcessGuid, Timestamp};

// ---------------------------------------------------------------------------
// Phase 1 structs — top-level EVTXECmd record
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RawEvtxRecord {
    #[serde(rename = "EventId")]
    pub event_id: u16,

    #[serde(rename = "TimeCreated")]
    pub time_created: String,

    #[serde(rename = "RecordNumber")]
    pub record_number: u64,

    #[serde(rename = "Payload")]
    pub payload: String,

    #[serde(rename = "Computer")]
    pub computer: String,

    #[serde(rename = "UserName")]
    pub user_name: Option<String>,

    #[serde(rename = "MapDescription")]
    pub map_description: Option<String>,

    #[serde(rename = "ExecutableInfo")]
    pub executable_info: Option<String>,

    #[serde(rename = "PayloadData1")]
    pub payload_data1: Option<String>,
    #[serde(rename = "PayloadData2")]
    pub payload_data2: Option<String>,
    #[serde(rename = "PayloadData3")]
    pub payload_data3: Option<String>,
    #[serde(rename = "PayloadData4")]
    pub payload_data4: Option<String>,
    #[serde(rename = "PayloadData5")]
    pub payload_data5: Option<String>,
    #[serde(rename = "PayloadData6")]
    pub payload_data6: Option<String>,
}

// ---------------------------------------------------------------------------
// Phase 2 structs — inner Payload JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PayloadWrapper {
    #[serde(rename = "EventData")]
    event_data: Option<EventDataWrapper>,
}

#[derive(Debug, Deserialize)]
struct EventDataWrapper {
    #[serde(rename = "Data", default)]
    data: Vec<DataField>,
}

#[derive(Debug, Deserialize)]
struct DataField {
    #[serde(rename = "@Name")]
    name: String,

    #[serde(rename = "#text")]
    text: Option<String>,
}

// ---------------------------------------------------------------------------
// Payload parsing
// ---------------------------------------------------------------------------

/// Parse the inner Payload JSON string into a flat `HashMap<field_name, value>`.
///
/// Falls back to a lenient pass that double-escapes stray backslashes if the
/// strict parse fails.  Some EVTXECmd versions emit Windows paths with single
/// backslashes inside JSON strings (e.g. `C:\Windows`) which are invalid JSON.
pub fn parse_payload(payload: &str) -> Result<HashMap<String, String>, serde_json::Error> {
    fn extract(wrapper: PayloadWrapper) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(ed) = wrapper.event_data {
            for field in ed.data {
                if let Some(text) = field.text {
                    map.insert(field.name, text);
                }
            }
        }
        map
    }

    // Fast path — standard strict parse.
    match serde_json::from_str::<PayloadWrapper>(payload) {
        Ok(w) => return Ok(extract(w)),
        Err(first_err) => {
            // Lenient fallback: double any backslash not part of a valid JSON
            // escape sequence so that Windows paths survive.
            let fixed = fix_unescaped_backslashes(payload);
            match serde_json::from_str::<PayloadWrapper>(&fixed) {
                Ok(w) => Ok(extract(w)),
                Err(_) => Err(first_err), // report the original error
            }
        }
    }
}

/// Double any backslash that is NOT already part of a recognised JSON escape
/// sequence (`\"`, `\\`, `\/`, `\uXXXX`).
///
/// Note: `\b`, `\f`, `\n`, `\r`, `\t` are valid JSON escapes but EVTXECmd
/// never intentionally produces them — they are Windows path separators that
/// were not double-escaped.  We treat them as stray backslashes too.
fn fix_unescaped_backslashes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() + 32);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // We have a backslash — check what follows.
        match bytes.get(i + 1).copied() {
            // Only keep escapes that EVTXECmd truly intends: \", \\, \/
            Some(b'"') | Some(b'\\') | Some(b'/') => {
                out.push(b'\\');
                out.push(bytes[i + 1]);
                i += 2;
            }
            Some(b'u') => {
                // \uXXXX — copy the whole 6-byte sequence verbatim.
                out.push(b'\\');
                out.push(b'u');
                i += 2;
                for _ in 0..4 {
                    if i < bytes.len() {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            _ => {
                // Stray backslash — escape it so JSON stays valid.
                out.push(b'\\');
                out.push(b'\\');
                i += 1;
            }
        }
    }
    // SAFETY: input was valid UTF-8; we only inserted ASCII bytes.
    unsafe { String::from_utf8_unchecked(out) }
}

// ---------------------------------------------------------------------------
// Field helper macros / functions
// ---------------------------------------------------------------------------


fn get_owned(fields: &HashMap<String, String>, key: &str) -> Option<String> {
    fields.get(key).cloned()
}

fn get_u32(fields: &HashMap<String, String>, key: &str) -> Option<u32> {
    fields.get(key)?.trim().parse().ok()
}

fn get_u16(fields: &HashMap<String, String>, key: &str) -> Option<u16> {
    fields.get(key)?.trim().parse().ok()
}

fn get_bool(fields: &HashMap<String, String>, key: &str) -> Option<bool> {
    match fields.get(key)?.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn get_guid(fields: &HashMap<String, String>, key: &str, line: u64, errors: &mut Vec<ParseError>) -> Option<ProcessGuid> {
    let s = fields.get(key)?;
    match parse_guid_opt(s) {
        Ok(g) => g,
        Err(e) => {
            errors.push(ParseError::InvalidGuid { line, guid: s.clone(), source: e });
            None
        }
    }
}

fn parse_timestamp(s: &str, line: u64, errors: &mut Vec<ParseError>) -> Option<Timestamp> {
    // EVTXECmd produces ISO 8601 timestamps, e.g. "2023-11-01T12:34:56.0000000Z"
    // Try a few formats.
    let s = s.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.into());
    }
    // Some variants omit the trailing Z or use different precision
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    // CSV format: "2023-05-03 11:15:12.2335395" (space separator, no timezone)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
    }
    errors.push(ParseError::InvalidTimestamp {
        line,
        value: s.to_owned(),
        source: chrono::DateTime::parse_from_rfc3339("bad").unwrap_err(),
    });
    None
}

// ---------------------------------------------------------------------------
// Event extraction
// ---------------------------------------------------------------------------

/// Build a `SysmonEvent` from the raw record + parsed field map.
///
/// `computer`, `image`, and `user` are interned into `rodeo` to deduplicate
/// the thousands of repeated strings across a large log file.
pub fn extract_event(
    raw: RawEvtxRecord,
    fields: &HashMap<String, String>,
    line: u64,
    errors: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) -> Option<SysmonEvent> {
    let event_type = SysmonEventType::from_event_id(raw.event_id);

    let time_created = parse_timestamp(&raw.time_created, line, errors)?;

    // Common per-process fields (present on most events but not all)
    let process_guid = get_guid(fields, "ProcessGuid", line, errors);
    let process_id = get_u32(fields, "ProcessId");
    // Intern highly-duplicated string fields for memory efficiency.
    let image = get_owned(fields, "Image").map(|s| rodeo.get_or_intern(s.as_str()));
    let user = raw.user_name.clone()
        .or_else(|| get_owned(fields, "User"))
        .map(|s| rodeo.get_or_intern(s.as_str()));
    let computer = rodeo.get_or_intern(raw.computer.as_str());
    let rule_name = get_owned(fields, "RuleName");
    let mitre_technique = rule_name.as_deref().and_then(parse_mitre_rule_name);

    let detail = build_detail(raw.event_id, fields, line, errors);

    Some(SysmonEvent {
        event_id: raw.event_id,
        event_type,
        time_created,
        record_number: raw.record_number,
        computer,
        process_guid,
        process_id,
        image,
        user,
        rule_name,
        mitre_technique,
        detail,
    })
}

fn build_detail(
    event_id: u16,
    fields: &HashMap<String, String>,
    line: u64,
    errors: &mut Vec<ParseError>,
) -> EventDetail {
    match event_id {
        // ProcessCreate
        1 => EventDetail::ProcessCreate {
            command_line: get_owned(fields, "CommandLine"),
            current_directory: get_owned(fields, "CurrentDirectory"),
            hashes: get_owned(fields, "Hashes"),
            parent_process_guid: get_guid(fields, "ParentProcessGuid", line, errors),
            parent_process_id: get_u32(fields, "ParentProcessId"),
            parent_image: get_owned(fields, "ParentImage"),
            parent_command_line: get_owned(fields, "ParentCommandLine"),
            parent_user: get_owned(fields, "ParentUser"),
            logon_guid: get_owned(fields, "LogonGuid"),
            logon_id: get_owned(fields, "LogonId"),
            terminal_session_id: get_u32(fields, "TerminalSessionId"),
            integrity_level: get_owned(fields, "IntegrityLevel"),
            file_version: get_owned(fields, "FileVersion"),
            description: get_owned(fields, "Description"),
            product: get_owned(fields, "Product"),
            company: get_owned(fields, "Company"),
            original_file_name: get_owned(fields, "OriginalFileName"),
        },

        // FileCreateTime
        2 => EventDetail::FileCreateTime {
            target_filename: get_owned(fields, "TargetFilename"),
            creation_utc_time: get_owned(fields, "CreationUtcTime"),
            previous_creation_utc_time: get_owned(fields, "PreviousCreationUtcTime"),
        },

        // NetworkConnect
        3 => EventDetail::NetworkConnect {
            protocol: get_owned(fields, "Protocol"),
            initiated: get_bool(fields, "Initiated"),
            source_ip: get_owned(fields, "SourceIp"),
            source_port: get_u16(fields, "SourcePort"),
            source_hostname: get_owned(fields, "SourceHostname"),
            destination_ip: get_owned(fields, "DestinationIp"),
            destination_port: get_u16(fields, "DestinationPort"),
            destination_hostname: get_owned(fields, "DestinationHostname"),
        },

        // SysmonServiceState (4) — minimal fields
        4 => EventDetail::Generic { fields: fields.clone() },

        // ProcessTerminate
        5 => EventDetail::ProcessTerminate,

        // DriverLoad
        6 => EventDetail::DriverLoad {
            image_loaded: get_owned(fields, "ImageLoaded"),
            hashes: get_owned(fields, "Hashes"),
            signature: get_owned(fields, "Signature"),
            signature_status: get_owned(fields, "SignatureStatus"),
        },

        // ImageLoad
        7 => EventDetail::ImageLoad {
            image_loaded: get_owned(fields, "ImageLoaded"),
            hashes: get_owned(fields, "Hashes"),
            signature: get_owned(fields, "Signature"),
            signature_status: get_owned(fields, "SignatureStatus"),
            signed: get_bool(fields, "Signed"),
        },

        // CreateRemoteThread
        8 => EventDetail::CreateRemoteThread {
            source_process_guid: get_guid(fields, "SourceProcessGuid", line, errors),
            source_process_id: get_u32(fields, "SourceProcessId"),
            source_image: get_owned(fields, "SourceImage"),
            target_process_guid: get_guid(fields, "TargetProcessGuid", line, errors),
            target_process_id: get_u32(fields, "TargetProcessId"),
            target_image: get_owned(fields, "TargetImage"),
            start_address: get_owned(fields, "StartAddress"),
            start_module: get_owned(fields, "StartModule"),
            start_function: get_owned(fields, "StartFunction"),
        },

        // RawAccessRead
        9 => EventDetail::RawAccessRead {
            device: get_owned(fields, "Device"),
        },

        // ProcessAccess
        10 => EventDetail::ProcessAccess {
            source_process_guid: get_guid(fields, "SourceProcessGuid", line, errors),
            source_process_id: get_u32(fields, "SourceProcessId"),
            source_image: get_owned(fields, "SourceImage"),
            target_process_guid: get_guid(fields, "TargetProcessGuid", line, errors),
            target_process_id: get_u32(fields, "TargetProcessId"),
            target_image: get_owned(fields, "TargetImage"),
            granted_access: get_owned(fields, "GrantedAccess"),
            call_trace: get_owned(fields, "CallTrace"),
        },

        // FileCreate
        11 => EventDetail::FileCreate {
            target_filename: get_owned(fields, "TargetFilename"),
            creation_utc_time: get_owned(fields, "CreationUtcTime"),
        },

        // RegistryCreateDelete
        12 => EventDetail::RegistryEvent {
            event_type: get_owned(fields, "EventType"),
            target_object: get_owned(fields, "TargetObject"),
            details: None,
            new_name: None,
        },

        // RegistryValueSet
        13 => EventDetail::RegistryEvent {
            event_type: get_owned(fields, "EventType"),
            target_object: get_owned(fields, "TargetObject"),
            details: get_owned(fields, "Details"),
            new_name: None,
        },

        // RegistryRename
        14 => EventDetail::RegistryEvent {
            event_type: get_owned(fields, "EventType"),
            target_object: get_owned(fields, "TargetObject"),
            details: None,
            new_name: get_owned(fields, "NewName"),
        },

        // FileCreateStreamHash
        15 => EventDetail::FileCreateStreamHash {
            target_filename: get_owned(fields, "TargetFilename"),
            hash: get_owned(fields, "Hash"),
            contents: get_owned(fields, "Contents"),
        },

        // SysmonConfigChange
        16 => EventDetail::SysmonConfigChange {
            configuration: get_owned(fields, "Configuration"),
            configuration_file_hash: get_owned(fields, "ConfigurationFileHash"),
        },

        // PipeCreated
        17 => EventDetail::PipeEvent {
            event_type: "CreatePipe".to_owned(),
            pipe_name: get_owned(fields, "PipeName"),
        },

        // PipeConnected
        18 => EventDetail::PipeEvent {
            event_type: "ConnectPipe".to_owned(),
            pipe_name: get_owned(fields, "PipeName"),
        },

        // WmiFilter / WmiConsumer / WmiBinding (19-21)
        19 | 20 | 21 => {
            let etype = match event_id {
                19 => "WmiFilter",
                20 => "WmiConsumer",
                _  => "WmiBinding",
            };
            EventDetail::WmiActivity {
                event_type: etype.to_owned(),
                operation: get_owned(fields, "Operation"),
                user: get_owned(fields, "User"),
                event_namespace: get_owned(fields, "EventNamespace"),
                name: get_owned(fields, "Name"),
                query: get_owned(fields, "Query"),
                destination: get_owned(fields, "Destination"),
                consumer_type: get_owned(fields, "Type"),
                filter_name: get_owned(fields, "FilterName"),
            }
        }

        // DnsQuery
        22 => EventDetail::DnsQuery {
            query_name: get_owned(fields, "QueryName"),
            query_status: get_owned(fields, "QueryStatus"),
            query_results: get_owned(fields, "QueryResults"),
        },

        // FileDelete (23) / FileDeleteDetected (26) / FileBlockExecutable (27) / FileBlockShredding (28) / FileExecutableDetected (29)
        23 | 26 | 27 | 28 | 29 => EventDetail::FileDeleteEvent {
            target_filename: get_owned(fields, "TargetFilename"),
            hashes: get_owned(fields, "Hashes"),
            is_executable: get_bool(fields, "IsExecutable"),
        },

        // ClipboardChange
        24 => EventDetail::ClipboardChange {
            session: get_owned(fields, "Session"),
            client_info: get_owned(fields, "ClientInfo"),
            hashes: get_owned(fields, "Hashes"),
        },

        // ProcessTampering
        25 => EventDetail::ProcessTampering {
            tampering_type: get_owned(fields, "Type"),
        },

        _ => EventDetail::Generic { fields: fields.clone() },
    }
}

// ---------------------------------------------------------------------------
// Streaming NDJSON parser
// ---------------------------------------------------------------------------

/// Batch size: number of events sent per channel message.
const BATCH_SIZE: usize = 500;

/// Parse an NDJSON file and stream `SysmonEvent` batches over `sender`.
///
/// `bytes_read` is updated atomically so callers can compute progress as
/// `bytes_read.load() / file_size`.
///
/// `rodeo` is the shared string interner — all `computer`, `image`, and `user`
/// fields in emitted events are interned keys.  The same `SharedRodeo` must be
/// used to resolve them later.
pub fn parse_file(
    path: &Path,
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    bytes_read: &Arc<AtomicU64>,
    errors_out: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(64 * 1024, file);

    let mut batch: Vec<SysmonEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut line_num: u64 = 0;

    for line_result in reader.lines() {
        line_num += 1;
        let line = line_result?;
        bytes_read.fetch_add(line.len() as u64 + 1, Ordering::Relaxed);

        // Strip UTF-8 BOM from the first line (some editors/tools emit it).
        let line = if line_num == 1 {
            line.trim_start_matches('\u{FEFF}').to_owned()
        } else {
            line
        };

        if line.trim().is_empty() {
            continue;
        }

        // Phase 1: deserialize top-level record
        // Apply the same lenient backslash fix as parse_payload: EVTXECmd may
        // write single backslashes (including \r, \t, \n, etc.) directly in
        // JSON strings.  Try strict parse first; fall back to the fixed line.
        let raw: RawEvtxRecord = {
            match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(first_err) => {
                    let fixed = fix_unescaped_backslashes(&line);
                    match serde_json::from_str::<RawEvtxRecord>(&fixed) {
                        Ok(r) => r,
                        Err(_) => {
                            errors_out.push(ParseError::TopLevelDeserialize {
                                line: line_num,
                                source: first_err,
                            });
                            continue;
                        }
                    }
                }
            }
        };

        // Phase 2: parse Payload field
        let fields = match parse_payload(&raw.payload) {
            Ok(f) => f,
            Err(e) => {
                errors_out.push(ParseError::PayloadDeserialize { line: line_num, source: e });
                continue;
            }
        };

        // Phase 3: extract typed SysmonEvent
        let mut local_errors = Vec::new();
        if let Some(event) = extract_event(raw, &fields, line_num, &mut local_errors, rodeo) {
            batch.push(event);
        }
        errors_out.extend(local_errors);

        if batch.len() >= BATCH_SIZE {
            let full_batch = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
            if sender.send(full_batch).is_err() {
                // Receiver dropped — stop parsing
                break;
            }
        }
    }

    // Flush remaining events
    if !batch.is_empty() {
        let _ = sender.send(batch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CSV parser (EVTXECmd CSV export)
// ---------------------------------------------------------------------------

/// Parse an EVTXECmd CSV export and stream `SysmonEvent` batches over `sender`.
pub fn parse_csv_file(
    path: &Path,
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    bytes_read: &Arc<AtomicU64>,
    errors_out: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) -> Result<()> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(BufReader::with_capacity(64 * 1024, file));

    // Build column index map from header names
    let headers = rdr.headers()?.clone();
    let col: HashMap<&str, usize> = headers.iter().enumerate().map(|(i, n)| (n, i)).collect();

    let idx_record_num  = col.get("RecordNumber").copied();
    let idx_event_id    = col.get("EventId").copied();
    let idx_time        = col.get("TimeCreated").copied();
    let idx_payload     = col.get("Payload").copied();
    let idx_computer    = col.get("Computer").copied();
    let idx_user        = col.get("UserName").copied();
    let idx_map_desc    = col.get("MapDescription").copied();
    let idx_exec_info   = col.get("ExecutableInfo").copied();
    let idx_pd1         = col.get("PayloadData1").copied();
    let idx_pd2         = col.get("PayloadData2").copied();
    let idx_pd3         = col.get("PayloadData3").copied();
    let idx_pd4         = col.get("PayloadData4").copied();
    let idx_pd5         = col.get("PayloadData5").copied();
    let idx_pd6         = col.get("PayloadData6").copied();

    let mut batch: Vec<SysmonEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut row_num: u64 = 0;

    for result in rdr.records() {
        row_num += 1;
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                errors_out.push(ParseError::CsvRowError { line: row_num, message: e.to_string() });
                continue;
            }
        };
        bytes_read.fetch_add(record.as_slice().len() as u64, Ordering::Relaxed);

        let get = |idx: Option<usize>| -> Option<&str> {
            idx.and_then(|i| record.get(i)).filter(|s| !s.is_empty())
        };

        let event_id: u16 = match get(idx_event_id).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        let record_number: u64 = get(idx_record_num).and_then(|s| s.parse().ok()).unwrap_or(row_num);
        let time_created = match get(idx_time) {
            Some(t) => t.to_owned(),
            None => continue,
        };
        let payload = match get(idx_payload) {
            Some(p) => p.to_owned(),
            None => continue,
        };
        let computer = get(idx_computer).unwrap_or("").to_owned();

        let raw = RawEvtxRecord {
            event_id,
            time_created,
            record_number,
            payload,
            computer,
            user_name:       get(idx_user).map(str::to_owned),
            map_description: get(idx_map_desc).map(str::to_owned),
            executable_info: get(idx_exec_info).map(str::to_owned),
            payload_data1:   get(idx_pd1).map(str::to_owned),
            payload_data2:   get(idx_pd2).map(str::to_owned),
            payload_data3:   get(idx_pd3).map(str::to_owned),
            payload_data4:   get(idx_pd4).map(str::to_owned),
            payload_data5:   get(idx_pd5).map(str::to_owned),
            payload_data6:   get(idx_pd6).map(str::to_owned),
        };

        let fields = match parse_payload(&raw.payload) {
            Ok(f) => f,
            Err(e) => {
                errors_out.push(ParseError::PayloadDeserialize { line: row_num, source: e });
                continue;
            }
        };

        let mut local_errors = Vec::new();
        if let Some(event) = extract_event(raw, &fields, row_num, &mut local_errors, rodeo) {
            batch.push(event);
        }
        errors_out.extend(local_errors);

        if batch.len() >= BATCH_SIZE {
            let full_batch = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
            if sender.send(full_batch).is_err() {
                break;
            }
        }
    }

    if !batch.is_empty() {
        let _ = sender.send(batch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Auto-detecting parser — dispatches to EVTX, CSV, or NDJSON
// ---------------------------------------------------------------------------

/// Parse a Sysmon log file, auto-detecting format by magic bytes and content.
///
/// - First 8 bytes == `ElfFile\0` → native EVTX binary parser
/// - First line starts with `{` → EVTXECmd NDJSON parser
/// - First line contains `RecordNumber` and commas → EVTXECmd CSV parser
/// - Otherwise → fall back to NDJSON parser
pub fn parse_file_auto(
    path: &Path,
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    bytes_read: &Arc<AtomicU64>,
    errors_out: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) -> Result<()> {
    const EVTX_SIG: u64 = 0x00656C6946666C45;
    let mut header = [0u8; 8];
    {
        use std::io::Read;
        let mut f = File::open(path)?;
        let n = f.read(&mut header)?;
        if n == 8 {
            let sig = u64::from_le_bytes(header);
            if sig == EVTX_SIG {
                return crate::evtx::parse_evtx_file(path, sender, bytes_read, errors_out, rodeo);
            }
        }
    }
    // Read first line to distinguish NDJSON from CSV
    {
        let f = File::open(path)?;
        let mut reader = BufReader::with_capacity(4096, f);
        let mut first_line = String::new();
        reader.read_line(&mut first_line)?;
        // Strip UTF-8 BOM (EF BB BF → U+FEFF) before format detection.
        let trimmed = first_line.trim_start_matches('\u{FEFF}').trim();
        if trimmed.starts_with('{') {
            return parse_file(path, sender, bytes_read, errors_out, rodeo);
        }
        if trimmed.contains("RecordNumber") && trimmed.contains(',') {
            return parse_csv_file(path, sender, bytes_read, errors_out, rodeo);
        }
    }
    parse_file(path, sender, bytes_read, errors_out, rodeo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_file_record_count() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.claude/sysmon2.csv");
        if !path.exists() {
            eprintln!("skipping test: {:?} not found", path);
            return;
        }
        let (sender, receiver) = crossbeam_channel::unbounded();
        let bytes_read = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let rodeo = crate::new_rodeo();
        let mut errors = Vec::new();
        parse_csv_file(&path, &sender, &bytes_read, &mut errors, &rodeo).unwrap();
        drop(sender);
        let events: Vec<_> = receiver.into_iter().flatten().collect();
        assert_eq!(events.len(), 3759, "expected 3759 events, got {}", events.len());
    }

    #[test]
    fn parse_payload_basic() {
        // Use r##"..."## so that the inner `#` does not terminate the raw string.
        let payload = r##"{"EventData":{"Data":[{"@Name":"ProcessGuid","#text":"{abc}"},{"@Name":"Image","#text":"C:\\foo.exe"}]}}"##;
        let map = parse_payload(payload).unwrap();
        assert_eq!(map.get("ProcessGuid").unwrap(), "{abc}");
        assert_eq!(map.get("Image").unwrap(), "C:\\foo.exe");
    }

    #[test]
    fn parse_payload_unescaped_backslash_paths() {
        // Simulates EVTXECmd output with single backslashes (not doubled).
        // \w, \S, \c are invalid JSON escapes; \t and \r are valid JSON escapes
        // that EVTXECmd never intends as control characters.
        let payload = "{\"EventData\":{\"Data\":[{\"@Name\":\"CommandLine\",\"#text\":\"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full\"}]}}";
        let map = parse_payload(payload).unwrap();
        let cmd = map.get("CommandLine").unwrap();
        assert!(cmd.contains("C:\\windows"), "expected backslash before 'windows', got: {cmd}");
        assert!(cmd.contains("\\System32"), "expected backslash before 'System32', got: {cmd}");
        assert!(cmd.contains("\\comsvcs"), "expected backslash before 'comsvcs', got: {cmd}");
        assert!(cmd.contains("C:\\temp"), "expected backslash before 'temp', got: {cmd}");
        assert!(cmd.contains("\\lsass"), "expected backslash before 'lsass', got: {cmd}");
    }

    #[test]
    fn parse_payload_missing_text_skipped() {
        let payload = r##"{"EventData":{"Data":[{"@Name":"EmptyField"}]}}"##;
        let map = parse_payload(payload).unwrap();
        assert!(map.get("EmptyField").is_none());
    }
}
