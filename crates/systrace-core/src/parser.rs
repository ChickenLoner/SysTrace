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
pub fn parse_payload(payload: &str) -> Result<HashMap<String, String>, serde_json::Error> {
    let wrapper: PayloadWrapper = serde_json::from_str(payload)?;
    let mut map = HashMap::new();
    if let Some(ed) = wrapper.event_data {
        for field in ed.data {
            if let Some(text) = field.text {
                map.insert(field.name, text);
            }
        }
    }
    Ok(map)
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
pub fn extract_event(
    raw: RawEvtxRecord,
    fields: &HashMap<String, String>,
    line: u64,
    errors: &mut Vec<ParseError>,
) -> Option<SysmonEvent> {
    let event_type = SysmonEventType::from_event_id(raw.event_id);

    let time_created = parse_timestamp(&raw.time_created, line, errors)?;

    // Common per-process fields (present on most events but not all)
    let process_guid = get_guid(fields, "ProcessGuid", line, errors);
    let process_id = get_u32(fields, "ProcessId");
    let image = get_owned(fields, "Image");
    // UserName from top-level, or from payload field "User"
    let user = raw.user_name.clone()
        .or_else(|| get_owned(fields, "User"));
    let rule_name = get_owned(fields, "RuleName");
    let mitre_technique = rule_name.as_deref().and_then(parse_mitre_rule_name);

    let detail = build_detail(raw.event_id, fields, line, errors);

    Some(SysmonEvent {
        event_id: raw.event_id,
        event_type,
        time_created,
        record_number: raw.record_number,
        computer: raw.computer,
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
pub fn parse_file(
    path: &Path,
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    bytes_read: &Arc<AtomicU64>,
    errors_out: &mut Vec<ParseError>,
) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(64 * 1024, file);

    let mut batch: Vec<SysmonEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut line_num: u64 = 0;

    for line_result in reader.lines() {
        line_num += 1;
        let line = line_result?;
        bytes_read.fetch_add(line.len() as u64 + 1, Ordering::Relaxed);

        if line.trim().is_empty() {
            continue;
        }

        // Phase 1: deserialize top-level record
        let raw: RawEvtxRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                errors_out.push(ParseError::TopLevelDeserialize { line: line_num, source: e });
                continue;
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
        if let Some(event) = extract_event(raw, &fields, line_num, &mut local_errors) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_payload_basic() {
        // Use r##"..."## so that the inner `#` does not terminate the raw string.
        let payload = r##"{"EventData":{"Data":[{"@Name":"ProcessGuid","#text":"{abc}"},{"@Name":"Image","#text":"C:\\foo.exe"}]}}"##;
        let map = parse_payload(payload).unwrap();
        assert_eq!(map.get("ProcessGuid").unwrap(), "{abc}");
        assert_eq!(map.get("Image").unwrap(), "C:\\foo.exe");
    }

    #[test]
    fn parse_payload_missing_text_skipped() {
        let payload = r##"{"EventData":{"Data":[{"@Name":"EmptyField"}]}}"##;
        let map = parse_payload(payload).unwrap();
        assert!(map.get("EmptyField").is_none());
    }
}
