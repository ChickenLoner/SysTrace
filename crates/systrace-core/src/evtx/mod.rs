//! Native EVTX binary parser for SysTrace.
//!
//! Parses Windows Event Log (.evtx) files directly, producing the same
//! `SysmonEvent` stream as the NDJSON parser — no EVTXECmd dependency required.
//!
//! Based on the binary format documented by EVTXECmd (Eric Zimmerman).

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;

use crate::event::SysmonEvent;
use crate::parser::{extract_event, RawEvtxRecord};
use crate::types::ParseError;

// ── Constants ─────────────────────────────────────────────────────────────────

const FILE_SIG: u64 = 0x00656C6946666C45; // "ElfFile\0" little-endian
const CHUNK_SIG: u64 = 0x006B6E6843666C45; // "ElfChnk\0" little-endian
const RECORD_SIG: u32 = 0x2A2A;
const CHUNK_SIZE: usize = 0x10000;
const FILE_HEADER_SIZE: usize = 0x1000;
const BATCH_SIZE: usize = 500;

const SYSMON_PROVIDER: &str = "Microsoft-Windows-Sysmon";

// ── Template node types ────────────────────────────────────────────────────────

/// A flat node in a pre-parsed BinXml template.
#[derive(Debug, Clone)]
enum TNode {
    OpenElem(String),       // <elem …
    Attr(String, TValue),   // name="value"
    CloseEmpty,             // />
    CloseElem,              // </elem>
    Text(TValue),           // element text content
}

/// A value that is either a literal string or a reference into the substitution array.
#[derive(Debug, Clone)]
enum TValue {
    Literal(String),
    Sub { id: u16, vtype: u16, optional: bool },
}

// ── Substitution entry ────────────────────────────────────────────────────────

struct SubEntry {
    size: usize,
    vtype: u16,
    data: Vec<u8>,
}

// ── Extracted event fields ────────────────────────────────────────────────────

#[derive(Default)]
struct EventFields {
    event_id: Option<u16>,
    time_created: Option<String>,
    record_number: u64,
    computer: Option<String>,
    provider: Option<String>,
    data: HashMap<String, String>,
}

// ── Cursor over chunk bytes ───────────────────────────────────────────────────

struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self { Self { buf, pos } }
    fn remaining(&self) -> usize { self.buf.len().saturating_sub(self.pos) }

    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn peek_u8(&self) -> Option<u8> { self.buf.get(self.pos).copied() }

    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() { return None; }
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Some(v)
    }
    fn read_i16(&mut self) -> Option<i16> { self.read_u16().map(|v| v as i16) }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() { return None; }
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Some(v)
    }
    fn read_i32(&mut self) -> Option<i32> { self.read_u32().map(|v| v as i32) }

    fn read_i64(&mut self) -> Option<i64> {
        if self.pos + 8 > self.buf.len() { return None; }
        let v = i64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Some(v)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() { return None; }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(b)
    }

    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }

    /// Read a string from the string table (chunk-relative offset).
    fn get_string(&self, strings: &mut HashMap<u32, String>, offset: u32) -> Option<String> {
        if let Some(s) = strings.get(&offset) { return Some(s.clone()); }
        let i = offset as usize;
        // Layout: 4 bytes unknown | 2 bytes hash | 2 bytes char_count | char_count*2 UTF-16LE
        if i + 8 > self.buf.len() { return None; }
        let char_len = u16::from_le_bytes([self.buf[i + 6], self.buf[i + 7]]) as usize;
        let end = i + 8 + char_len * 2;
        if end > self.buf.len() { return None; }
        let s = decode_utf16le(&self.buf[i + 8..end]);
        strings.insert(offset, s.clone());
        Some(s)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn decode_utf16le(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&words);
    s.trim_end_matches('\0').to_string()
}

fn filetime_to_rfc3339(ft: i64) -> String {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000i64;
    if ft <= 0 { return String::new(); }
    let unix_100ns = match ft.checked_sub(EPOCH_DIFF) {
        Some(v) if v >= 0 => v,
        _ => return String::new(),
    };
    let secs = unix_100ns / 10_000_000;
    let subsec_ns = ((unix_100ns % 10_000_000) * 100) as u32;
    match chrono::DateTime::from_timestamp(secs, subsec_ns) {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        None => String::new(),
    }
}

fn decode_value(data: &[u8], vtype: u16) -> String {
    if data.is_empty() { return String::new(); }
    match vtype {
        0x00 => String::new(), // NullType
        0x01 => decode_utf16le(data).trim_end_matches('\0').to_string(), // StringType
        0x02 => {
            // AnsiStringType (CP1252 → approximate with latin-1)
            data.iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect()
        }
        0x03 => (data[0] as i8).to_string(),  // Int8
        0x04 => data[0].to_string(),           // UInt8
        0x05 => {                              // Int16
            if data.len() < 2 { return String::new(); }
            i16::from_le_bytes([data[0], data[1]]).to_string()
        }
        0x06 => {                              // UInt16
            if data.len() < 2 { return String::new(); }
            u16::from_le_bytes([data[0], data[1]]).to_string()
        }
        0x07 => {                              // Int32
            if data.len() < 4 { return String::new(); }
            i32::from_le_bytes(data[..4].try_into().unwrap()).to_string()
        }
        0x08 => {                              // UInt32
            if data.len() < 4 { return String::new(); }
            u32::from_le_bytes(data[..4].try_into().unwrap()).to_string()
        }
        0x09 => {                              // Int64
            if data.len() < 8 { return String::new(); }
            i64::from_le_bytes(data[..8].try_into().unwrap()).to_string()
        }
        0x0A => {                              // UInt64
            if data.len() < 8 { return String::new(); }
            u64::from_le_bytes(data[..8].try_into().unwrap()).to_string()
        }
        0x0D => {                              // BoolType (32-bit)
            if data.len() < 4 { return String::new(); }
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            if v != 0 { "true".to_string() } else { "false".to_string() }
        }
        0x0E => {                              // BinaryType → hex
            data.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
        }
        0x0F => {                              // GuidType (Windows mixed-endian, 16 bytes)
            if data.len() < 16 { return String::new(); }
            let bytes: [u8; 16] = data[..16].try_into().unwrap();
            let uuid = uuid::Uuid::from_bytes_le(bytes);
            format!("{{{}}}", uuid)
        }
        0x11 => {                              // FileTimeType (i64 FILETIME)
            if data.len() < 8 { return String::new(); }
            let ft = i64::from_le_bytes(data[..8].try_into().unwrap());
            filetime_to_rfc3339(ft)
        }
        0x12 => {                              // SysTimeType (SYSTEMTIME struct, 16 bytes)
            if data.len() < 16 { return String::new(); }
            let year  = u16::from_le_bytes([data[0], data[1]]);
            let month = u16::from_le_bytes([data[2], data[3]]);
            let day   = u16::from_le_bytes([data[6], data[7]]);
            let hour  = u16::from_le_bytes([data[8], data[9]]);
            let min   = u16::from_le_bytes([data[10], data[11]]);
            let sec   = u16::from_le_bytes([data[12], data[13]]);
            let ms    = u16::from_le_bytes([data[14], data[15]]);
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z")
        }
        0x13 => {                              // SidType → "S-1-..."
            if data.len() < 8 { return String::new(); }
            let version = data[0];
            let sub_count = data[1] as usize;
            let auth = u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);
            let mut sid = format!("S-{version}-{auth}");
            for i in 0..sub_count {
                let off = 8 + i * 4;
                if off + 4 > data.len() { break; }
                let sub = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
                sid.push('-');
                sid.push_str(&sub.to_string());
            }
            sid
        }
        0x14 => {                              // HexInt32
            if data.len() < 4 { return String::new(); }
            format!("0x{:X}", i32::from_le_bytes(data[..4].try_into().unwrap()))
        }
        0x15 => {                              // HexInt64
            if data.len() < 8 { return String::new(); }
            format!("0x{:X}", i64::from_le_bytes(data[..8].try_into().unwrap()))
        }
        _ => String::new(),
    }
}

fn resolve_tvalue(v: &TValue, subs: &[SubEntry]) -> String {
    match v {
        TValue::Literal(s) => s.clone(),
        TValue::Sub { id, optional, .. } => {
            let idx = *id as usize;
            if idx >= subs.len() { return String::new(); }
            let entry = &subs[idx];
            if *optional && entry.vtype == 0x00 { return String::new(); }
            decode_value(&entry.data, entry.vtype)
        }
    }
}

// ── Template BinXml parser ────────────────────────────────────────────────────

/// Parse a BinXml stream from `cur.pos` up to `end` into a flat `Vec<TNode>`.
fn parse_binxml(cur: &mut Cur, strings: &mut HashMap<u32, String>, end: usize) -> Vec<TNode> {
    let mut nodes = Vec::new();
    while cur.pos < end {
        let opcode = match cur.read_u8() { Some(b) => b, None => break };
        match opcode {
            0x0F => { cur.skip(3); } // StartOfBXmlStream — major(1) + minor(1) + flags(1)
            0x00 => break, // EndOfBXmlStream
            0x04 => { nodes.push(TNode::CloseElem); }
            0x01 | 0x41 => parse_open_element(cur, strings, opcode == 0x41, end, &mut nodes),
            0x05 | 0x45 => { // Value — literal element text content
                let vtype = cur.read_u8().unwrap_or(0);
                let size_chars = cur.read_i16().unwrap_or(0) as usize;
                if vtype == 0x01 { // StringType: size_chars × UTF-16LE
                    let bytes = cur.read_bytes(size_chars * 2).unwrap_or(&[]);
                    nodes.push(TNode::Text(TValue::Literal(decode_utf16le(bytes))));
                } else {
                    cur.skip(size_chars);
                }
            }
            0x0D => { // NormalSubstitution (element text)
                let id = cur.read_u16().unwrap_or(0);
                let vtype = cur.read_u8().unwrap_or(0) as u16;
                nodes.push(TNode::Text(TValue::Sub { id, vtype, optional: false }));
            }
            0x0E => { // OptionalSubstitution (element text)
                let id = cur.read_u16().unwrap_or(0);
                let vtype = cur.read_u8().unwrap_or(0) as u16;
                nodes.push(TNode::Text(TValue::Sub { id, vtype, optional: true }));
            }
            _ => { cur.pos = end; break; } // Unknown opcode: advance to end, stop
        }
    }
    nodes
}

fn parse_open_element(
    cur: &mut Cur,
    strings: &mut HashMap<u32, String>,
    has_attr: bool,
    parent_end: usize,
    nodes: &mut Vec<TNode>,
) {
    let _sub_slot = cur.read_i16();
    let size = match cur.read_i32() { Some(v) => v as usize, None => return };
    let start_pos = cur.pos; // chunk-relative position AFTER reading size field

    let name_offset = match cur.read_u32() { Some(v) => v, None => return };
    let name = match cur.get_string(strings, name_offset) { Some(s) => s, None => return };

    // Skip inline string definition if this string is defined at the current position
    // (name_offset >= start_pos means the string definition appears here in the stream)
    if name_offset as usize >= start_pos {
        let char_len = strings.get(&name_offset)
            .map(|s| s.chars().count())
            .unwrap_or(0);
        let entry_size = 4 + 2 + 2 + char_len * 2 + 2;
        cur.skip(entry_size);
    }

    nodes.push(TNode::OpenElem(name));

    if has_attr {
        let attr_size = match cur.read_i32() { Some(v) => v as usize, None => return };
        let attr_end = cur.pos + attr_size;
        while cur.pos < attr_end {
            // Each attribute: [opcode(1)][nameOffset(4)][value...] — NO per-attr size prefix
            let op = match cur.read_u8() { Some(b) => b, None => break };
            if op != 0x06 && op != 0x46 { break; }
            parse_attribute(cur, strings, nodes);
        }
        // Ensure we're at attr_end
        if cur.pos < attr_end { cur.pos = attr_end; }
    }

    // CloseStartElement (0x02) or CloseEmptyElement (0x03)
    let close_op = match cur.read_u8() { Some(b) => b, None => return };
    if close_op == 0x03 {
        nodes.push(TNode::CloseEmpty);
        return;
    }

    // Parse children until size exhausted
    let end = (start_pos + size).min(parent_end).min(cur.buf.len());
    let mut child_nodes = parse_binxml(cur, strings, end);
    nodes.append(&mut child_nodes);
    // Ensure EndElement is emitted
    if !matches!(nodes.last(), Some(TNode::CloseElem)) {
        nodes.push(TNode::CloseElem);
    }
}

fn parse_attribute(cur: &mut Cur, strings: &mut HashMap<u32, String>, nodes: &mut Vec<TNode>) {
    let name_offset = match cur.read_u32() { Some(v) => v, None => return };
    let name = match cur.get_string(strings, name_offset) { Some(s) => s, None => return };

    // Skip inline string definition if forward reference
    if name_offset as usize >= cur.pos - 4 {
        let char_len = strings.get(&name_offset).map(|s| s.chars().count()).unwrap_or(0);
        let entry_size = 4 + 2 + 2 + char_len * 2 + 2;
        cur.skip(entry_size);
    }

    // Value: Value(0x05), NormalSubstitution(0x0D), or OptionalSubstitution(0x0E)
    let val_op = match cur.read_u8() { Some(b) => b, None => return };
    let val = match val_op {
        0x05 | 0x45 => {
            let vtype = cur.read_u8().unwrap_or(0);
            let size_chars = cur.read_i16().unwrap_or(0) as usize;
            if vtype == 0x01 {
                let bytes = cur.read_bytes(size_chars * 2).unwrap_or(&[]);
                TValue::Literal(decode_utf16le(bytes))
            } else {
                cur.skip(size_chars);
                TValue::Literal(String::new())
            }
        }
        0x0D => {
            let id = cur.read_u16().unwrap_or(0);
            let vtype = cur.read_u8().unwrap_or(0) as u16;
            TValue::Sub { id, vtype, optional: false }
        }
        0x0E => {
            let id = cur.read_u16().unwrap_or(0);
            let vtype = cur.read_u8().unwrap_or(0) as u16;
            TValue::Sub { id, vtype, optional: true }
        }
        _ => TValue::Literal(String::new()),
    };

    nodes.push(TNode::Attr(name, val));
}

// ── Template pre-parsing from chunk header ────────────────────────────────────

/// Parse all templates from the template table at offset 0x180 in the chunk.
/// Returns a map: templateOffset (i32) → Vec<TNode>.
fn parse_templates(
    chunk: &[u8],
    strings: &mut HashMap<u32, String>,
) -> HashMap<i32, Vec<TNode>> {
    let mut templates: HashMap<i32, Vec<TNode>> = HashMap::new();
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for i in 0..32usize {
        let off = 0x180 + i * 4;
        let table_offset = match (off + 4 <= chunk.len())
            .then(|| u32::from_le_bytes(chunk[off..off + 4].try_into().unwrap()) as usize)
        {
            Some(v) if v > 0 => v,
            _ => continue,
        };

        // Template header is at table_offset - 10 (empirical offset from EVTXECmd)
        let start = if table_offset >= 10 { table_offset - 10 } else { continue };
        parse_template_at(chunk, start, strings, &mut templates, &mut visited);
    }

    templates
}

fn parse_template_at(
    chunk: &[u8],
    start: usize,
    strings: &mut HashMap<u32, String>,
    templates: &mut HashMap<i32, Vec<TNode>>,
    visited: &mut std::collections::HashSet<usize>,
) {
    if !visited.insert(start) { return; }
    if start >= chunk.len() { return; }

    // Check for 0x0C opcode
    let mut idx = start;
    if chunk.get(idx) != Some(&0x0C) {
        // Try 10 bytes before
        if start < 10 { return; }
        idx = start - 10;
        if chunk.get(idx) != Some(&0x0C) { return; }
    }
    idx += 1; // skip opcode
    if idx + 14 > chunk.len() { return; }

    let _version = chunk[idx]; idx += 1;
    let _template_id = i32::from_le_bytes(chunk[idx..idx + 4].try_into().unwrap()); idx += 4;
    let template_offset = i32::from_le_bytes(chunk[idx..idx + 4].try_into().unwrap()); idx += 4;
    let next_template_offset = i32::from_le_bytes(chunk[idx..idx + 4].try_into().unwrap()); idx += 4;

    if template_offset == 0 { return; }

    // Skip GUID (16 bytes)
    if idx + 20 > chunk.len() { return; }
    idx += 16;

    let length = i32::from_le_bytes(chunk[idx..idx + 4].try_into().unwrap()) as usize; idx += 4;
    if idx + length > chunk.len() { return; }

    // Parse template BinXml
    let template_end = idx + length;
    let mut cur = Cur::new(chunk, idx);
    let nodes = parse_binxml(&mut cur, strings, template_end);

    templates.insert(template_offset, nodes);

    // Follow template chain
    if next_template_offset > 0 {
        let next_start = if next_template_offset as usize >= 10 {
            next_template_offset as usize - 10
        } else {
            return;
        };
        parse_template_at(chunk, next_start, strings, templates, visited);
    }
}

// ── String table pre-parsing ──────────────────────────────────────────────────

fn build_string_table(chunk: &[u8], table_offset: usize) -> HashMap<u32, String> {
    let mut strings = HashMap::new();
    for i in 0..64usize {
        let off = table_offset + i * 4;
        if off + 4 > chunk.len() { break; }
        let str_offset = u32::from_le_bytes(chunk[off..off + 4].try_into().unwrap());
        if str_offset == 0 { continue; }

        let i = str_offset as usize;
        if i + 8 > chunk.len() { continue; }
        let char_len = u16::from_le_bytes([chunk[i + 6], chunk[i + 7]]) as usize;
        let end = i + 8 + char_len * 2;
        if end > chunk.len() { continue; }
        let s = decode_utf16le(&chunk[i + 8..end]);
        strings.insert(str_offset, s);
    }
    strings
}

// ── Substitution array parsing ────────────────────────────────────────────────

fn read_substitutions(cur: &mut Cur, count: usize) -> Vec<SubEntry> {
    let mut entries: Vec<SubEntry> = Vec::with_capacity(count);
    for _ in 0..count {
        let size = cur.read_u16().unwrap_or(0) as usize;
        let vtype = cur.read_u16().unwrap_or(0);
        entries.push(SubEntry { size, vtype, data: Vec::new() });
    }
    for entry in &mut entries {
        let bytes = cur.read_bytes(entry.size).unwrap_or(&[]);
        entry.data = bytes.to_vec();
    }
    entries
}

// ── Record BinXml parsing ─────────────────────────────────────────────────────

/// Parse the BinXml payload of an event record (after the 24-byte record header).
///
/// Sysmon record BinXml layout:
///   0x0F  StartOfBXmlStream
///   0x0C  TemplateInstance
///   0x00  EndOfBXmlStream
fn parse_record_payload(
    chunk: &[u8],
    payload_start: usize,
    record_chunk_offset: usize,
    templates: &HashMap<i32, Vec<TNode>>,
    strings: &mut HashMap<u32, String>,
) -> Option<(i32, Vec<SubEntry>)> {
    let mut cur = Cur::new(chunk, payload_start);

    // Expect StartOfBXmlStream (0x0F) + 3 bytes (major, minor, flags)
    if cur.read_u8()? != 0x0F { return None; }
    cur.skip(3); // major, minor, flags

    // Expect TemplateInstance (0x0C)
    if cur.read_u8()? != 0x0C { return None; }

    // Parse TemplateInstance header
    let _version = cur.read_u8()?;
    let _template_id = cur.read_i32()?;
    let template_offset = cur.read_i32()?;

    // Determine if this is an old (back-reference) or new (inline) template.
    // Old template: template_offset < record_chunk_offset — no extra bytes in stream.
    // New template: stream contains nextTemplateOffset + guid + length + template_bytes.
    let is_old = (template_offset as usize) < record_chunk_offset;

    if is_old {
        // Stream is now at subCount — nothing to skip
    } else {
        // New template: skip nextTemplateOffset(4) + guid(16) + length(4) + template_bytes
        let _next = cur.read_i32()?;
        cur.skip(16); // guid
        let tmpl_size = cur.read_i32()? as usize;
        cur.skip(tmpl_size);
    }

    // Substitution array
    let sub_count = cur.read_i32()? as usize;
    let subs = read_substitutions(&mut cur, sub_count);

    Some((template_offset, subs))
}

// ── Field extraction from template + substitutions ───────────────────────────

fn extract_event_fields(
    nodes: &[TNode],
    subs: &[SubEntry],
    record_number: u64,
    record_chunk_offset: usize,
    templates: &HashMap<i32, Vec<TNode>>,
) -> EventFields {
    let mut fields = EventFields { record_number, ..Default::default() };
    extract_into_fields(nodes, subs, record_chunk_offset, templates, &mut fields);
    fields
}

fn extract_into_fields(
    nodes: &[TNode],
    subs: &[SubEntry],
    record_chunk_offset: usize,
    templates: &HashMap<i32, Vec<TNode>>,
    fields: &mut EventFields,
) {
    let mut stack: Vec<String> = Vec::new();
    let mut in_event_data = false;
    let mut current_data_name: Option<String> = None;

    for node in nodes {
        match node {
            TNode::OpenElem(name) => {
                if in_event_data && name == "Data" {
                    current_data_name = None;
                }
                if name == "EventData" {
                    in_event_data = true;
                }
                stack.push(name.clone());
            }
            TNode::Attr(name, val) => {
                let elem = stack.last().map(|s| s.as_str()).unwrap_or("");
                match (elem, name.as_str()) {
                    ("Provider", "Name") => {
                        fields.provider = Some(resolve_tvalue(val, subs));
                    }
                    ("TimeCreated", "SystemTime") => {
                        fields.time_created = Some(resolve_tvalue(val, subs));
                    }
                    ("Data", "Name") if in_event_data => {
                        current_data_name = Some(resolve_tvalue(val, subs));
                    }
                    _ => {}
                }
            }
            TNode::Text(val) => {
                // Handle BinXml substitution (EventData embedded as BinXml type 0x21)
                if let TValue::Sub { id, vtype: 0x21, .. } = val {
                    let idx = *id as usize;
                    if idx < subs.len() {
                        parse_binxml_sub_into(&subs[idx].data, record_chunk_offset, templates, fields);
                    }
                    continue;
                }
                let value = resolve_tvalue(val, subs);
                if value.is_empty() { continue; }
                let elem = stack.last().map(|s| s.as_str()).unwrap_or("");
                match elem {
                    "EventID" => { fields.event_id = value.parse().ok(); }
                    "Computer" => { fields.computer = Some(value); }
                    "Data" if in_event_data => {
                        if let Some(ref dn) = current_data_name {
                            fields.data.insert(dn.clone(), value);
                        }
                    }
                    _ => {}
                }
            }
            TNode::CloseElem | TNode::CloseEmpty => {
                if let Some(name) = stack.pop() {
                    if name == "EventData" { in_event_data = false; }
                }
                current_data_name = None;
            }
        }
    }
}

/// Parse a BinXml substitution blob (starts with 0x0C TemplateInstance, no 0x0F prefix).
///
/// `record_chunk_offset`: chunk-relative start of the enclosing record.
/// If `template_offset >= record_chunk_offset`, the template is defined inline
/// in this blob (new template) and we must skip nextTemplateOffset+guid+length+bytes
/// before the substitution descriptor array. Otherwise it is a back-reference (old).
fn parse_binxml_sub_into(
    data: &[u8],
    record_chunk_offset: usize,
    templates: &HashMap<i32, Vec<TNode>>,
    fields: &mut EventFields,
) {
    let mut cur = Cur::new(data, 0);
    // Expect TemplateInstance opcode 0x0C
    if cur.read_u8() != Some(0x0C) { return; }
    let _version = cur.read_u8();
    let _template_id = cur.read_i32();
    let template_offset = match cur.read_i32() { Some(v) => v, None => return };

    // Determine old (back-reference) vs new (inline template definition)
    let is_old = (template_offset as usize) < record_chunk_offset;
    if !is_old {
        // New: skip nextTemplateOffset(4) + guid(16) + length(4) + template_bytes
        let _next = cur.read_i32();
        cur.skip(16); // guid
        let tmpl_size = match cur.read_i32() { Some(v) => v as usize, None => return };
        cur.skip(tmpl_size); // inline template BinXml (already pre-parsed into templates map)
    }

    let sub_count = match cur.read_i32() { Some(v) => v as usize, None => return };
    let inner_subs = read_substitutions(&mut cur, sub_count);
    if let Some(tmpl_nodes) = templates.get(&template_offset) {
        extract_into_fields(tmpl_nodes, &inner_subs, record_chunk_offset, templates, fields);
    }
}

// ── Chunk processing ──────────────────────────────────────────────────────────

fn process_chunk(
    chunk: &[u8],
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    batch: &mut Vec<SysmonEvent>,
    errors: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) {
    // Validate chunk signature
    if chunk.len() < 0x200 { return; }
    let sig = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
    if sig != CHUNK_SIG { return; }

    let first_id = i64::from_le_bytes(chunk[0x18..0x20].try_into().unwrap());
    if first_id == -1 { return; } // empty chunk

    let last_id = i64::from_le_bytes(chunk[0x20..0x28].try_into().unwrap());

    let table_offset = u32::from_le_bytes(chunk[0x28..0x2C].try_into().unwrap()) as usize;
    let last_record_offset = u32::from_le_bytes(chunk[0x2C..0x30].try_into().unwrap()) as usize;

    // Build string table
    let mut strings = build_string_table(chunk, table_offset);

    // Build template cache
    let templates = parse_templates(chunk, &mut strings);

    // Records start at table_offset + string_table(0x100) + template_table(0x80)
    let records_start = table_offset + 0x100 + 0x80;
    let mut pos = records_start;

    while pos + 4 <= chunk.len() {
        // Check record signature
        if pos > last_record_offset { break; }
        let sig = u32::from_le_bytes(chunk[pos..pos + 4].try_into().unwrap());
        if sig != RECORD_SIG { break; }

        if pos + 8 > chunk.len() { break; }
        let record_size = u32::from_le_bytes(chunk[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if record_size < 24 || pos + record_size > chunk.len() { break; }

        let record_number = i64::from_le_bytes(chunk[pos + 8..pos + 16].try_into().unwrap());

        // Skip records outside valid range
        if record_number < first_id || record_number > last_id {
            pos += record_size;
            continue;
        }

        let timestamp_ft = i64::from_le_bytes(chunk[pos + 16..pos + 24].try_into().unwrap());
        let record_chunk_offset = pos;

        // Parse BinXml payload (starts at +24, after signature+size+recnum+timestamp)
        let payload_start = pos + 24;
        let payload_result = parse_record_payload(
            chunk,
            payload_start,
            record_chunk_offset,
            &templates,
            &mut strings,
        );

        if let Some((template_offset, subs)) = payload_result {
            if let Some(tmpl_nodes) = templates.get(&template_offset) {
                let efields = extract_event_fields(tmpl_nodes, &subs, record_number as u64, record_chunk_offset, &templates);

                // Filter to Sysmon events only
                let is_sysmon = efields.provider
                    .as_deref()
                    .map(|p| p == SYSMON_PROVIDER)
                    .unwrap_or(false);

                if is_sysmon {
                    if let Some(event_id) = efields.event_id {
                        // Use FILETIME timestamp as fallback if BinXml didn't yield TimeCreated
                        let time_str = efields.time_created
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| filetime_to_rfc3339(timestamp_ft));

                        let raw = RawEvtxRecord {
                            event_id,
                            time_created: time_str,
                            record_number: record_number as u64,
                            payload: String::new(),
                            computer: efields.computer.unwrap_or_default(),
                            user_name: None,
                            map_description: None,
                            executable_info: None,
                            payload_data1: None,
                            payload_data2: None,
                            payload_data3: None,
                            payload_data4: None,
                            payload_data5: None,
                            payload_data6: None,
                        };

                        let mut local_errors = Vec::new();
                        if let Some(event) = extract_event(raw, &efields.data, record_number as u64, &mut local_errors, rodeo) {
                            batch.push(event);
                        }
                        errors.extend(local_errors);
                    }
                }
            }
        }

        pos += record_size;

        if batch.len() >= BATCH_SIZE {
            let full = std::mem::replace(batch, Vec::with_capacity(BATCH_SIZE));
            if sender.send(full).is_err() { return; }
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse a raw `.evtx` file and stream `SysmonEvent` batches over `sender`.
///
/// Only Sysmon events (Provider = "Microsoft-Windows-Sysmon") are emitted.
/// Both format detection and field extraction are done natively — no EVTXECmd required.
pub fn parse_evtx_file(
    path: &Path,
    sender: &crossbeam_channel::Sender<Vec<SysmonEvent>>,
    bytes_read: &Arc<AtomicU64>,
    errors_out: &mut Vec<ParseError>,
    rodeo: &crate::SharedRodeo,
) -> Result<()> {
    let data = std::fs::read(path)?;

    if data.len() < FILE_HEADER_SIZE {
        anyhow::bail!("File too small to be a valid EVTX file");
    }

    // Validate file signature
    let sig = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if sig != FILE_SIG {
        anyhow::bail!("Invalid EVTX file signature");
    }

    let chunk_count = u16::from_le_bytes(data[0x2A..0x2C].try_into().unwrap()) as usize;

    let mut batch: Vec<SysmonEvent> = Vec::with_capacity(BATCH_SIZE);

    for chunk_idx in 0..chunk_count {
        let chunk_start = FILE_HEADER_SIZE + chunk_idx * CHUNK_SIZE;
        let chunk_end = (chunk_start + CHUNK_SIZE).min(data.len());
        if chunk_start >= data.len() { break; }
        let chunk = &data[chunk_start..chunk_end];

        bytes_read.fetch_add(chunk.len() as u64, Ordering::Relaxed);

        process_chunk(chunk, sender, &mut batch, errors_out, rodeo);

        if batch.len() >= BATCH_SIZE {
            let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
            if sender.send(full).is_err() { break; }
        }
    }

    if !batch.is_empty() {
        let _ = sender.send(batch);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    fn evtx_path() -> std::path::PathBuf {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.join("../../evtx/Microsoft-Windows-Sysmon%4Operational.evtx")
    }

    /// Diagnostic: inspect raw chunk/template/record counts without full extraction.
    #[test]
    fn diagnose_evtx_structure() {
        let path = evtx_path();
        if !path.exists() { eprintln!("test file missing"); return; }
        let data = std::fs::read(&path).unwrap();
        println!("File size: {} bytes", data.len());

        let sig = u64::from_le_bytes(data[0..8].try_into().unwrap());
        println!("File sig: 0x{sig:016X} (expected 0x{FILE_SIG:016X})");

        let chunk_count = u16::from_le_bytes(data[0x2A..0x2C].try_into().unwrap()) as usize;
        println!("Chunk count: {chunk_count}");

        for ci in 0..chunk_count.min(3) {
            let cs = FILE_HEADER_SIZE + ci * CHUNK_SIZE;
            let ce = (cs + CHUNK_SIZE).min(data.len());
            let chunk = &data[cs..ce];
            let csig = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let first_id = i64::from_le_bytes(chunk[0x18..0x20].try_into().unwrap());
            let last_id = i64::from_le_bytes(chunk[0x20..0x28].try_into().unwrap());
            let table_offset = u32::from_le_bytes(chunk[0x28..0x2C].try_into().unwrap()) as usize;
            let last_rec_off = u32::from_le_bytes(chunk[0x2C..0x30].try_into().unwrap()) as usize;
            println!("Chunk {ci}: sig=0x{csig:016X} first_id={first_id} last_id={last_id} table_off=0x{table_offset:X} last_rec=0x{last_rec_off:X}");

            // Check templates
            let mut strings = build_string_table(chunk, table_offset);
            let templates = parse_templates(chunk, &mut strings);
            println!("  Templates: {} cached, strings: {}", templates.len(), strings.len());
            for (k, v) in &templates {
                println!("    Template offset 0x{k:X}: {} nodes", v.len());
                for (i, n) in v.iter().enumerate() {
                    println!("      [{i}] {:?}", n);
                }
            }

            // Check records
            let records_start = table_offset + 0x100 + 0x80;
            let mut pos = records_start;
            let mut rec_count = 0;
            while pos + 4 <= chunk.len() {
                if pos > last_rec_off { break; }
                let rsig = u32::from_le_bytes(chunk[pos..pos+4].try_into().unwrap());
                if rsig != RECORD_SIG { break; }
                let rsize = u32::from_le_bytes(chunk[pos+4..pos+8].try_into().unwrap()) as usize;
                if rsize < 24 || pos + rsize > chunk.len() { break; }
                rec_count += 1;

                if rec_count <= 2 {
                    // Try to parse payload
                    let result = parse_record_payload(chunk, pos + 24, pos, &templates, &mut strings);
                    if let Some((toff, subs)) = result {
                        if let Some(tmpl) = templates.get(&toff) {
                            let ef = extract_event_fields(tmpl, &subs, 0, pos, &templates);
                            println!("  Record {rec_count}: toff=0x{toff:X} subs={} event_id={:?} provider={:?} computer={:?}",
                                subs.len(), ef.event_id, ef.provider, ef.computer);
                            println!("    data keys: {:?}", ef.data.keys().take(5).collect::<Vec<_>>());
                        } else {
                            println!("  Record {rec_count}: toff=0x{toff:X} NOT IN CACHE");
                        }
                    } else {
                        println!("  Record {rec_count}: payload parse FAILED");
                        // Print first few bytes of payload
                        let pay = &chunk[pos+24..std::cmp::min(pos+50, chunk.len())];
                        println!("    payload bytes: {:02X?}", pay);
                    }
                }
                pos += rsize;
            }
            println!("  Total records in chunk: {rec_count}");
        }
    }

    /// Byte dump at specific positions in template 0x226 BinXml.
    #[test]
    fn dump_template_tail() {
        let path = evtx_path();
        if !path.exists() { return; }
        let data = std::fs::read(&path).unwrap();
        let chunk = &data[FILE_HEADER_SIZE..FILE_HEADER_SIZE + CHUNK_SIZE];
        // Template 0x226: BinXml at 0x23E, length=1174
        let binxml_start = 0x23Eusize;
        let length = 1174usize;
        let end = binxml_start + length;
        // Print last 200 bytes of template BinXml to see Computer+Security+EventData
        let start_dump = end.saturating_sub(200);
        println!("Template 0x226 BinXml tail (0x{start_dump:X}..0x{end:X}):");
        for i in (start_dump..end).step_by(16) {
            let row_end = (i + 16).min(end);
            let hex: Vec<String> = chunk[i..row_end].iter().map(|b| format!("{b:02X}")).collect();
            println!("  0x{i:04X}: {}", hex.join(" "));
        }
    }

    /// Byte dump of template 0x226's BinXml to understand attribute structure.
    #[test]
    fn dump_template_bytes() {
        let path = evtx_path();
        if !path.exists() { return; }
        let data = std::fs::read(&path).unwrap();
        let chunk = &data[FILE_HEADER_SIZE..FILE_HEADER_SIZE + CHUNK_SIZE];
        // template 0x226 → 0x0C is at 0x226 - 10 = 0x21C
        let start = 0x226usize - 10;
        // header: 0x0C(1)+ver(1)+id(4)+offset(4)+next(4)+guid(16)+length(4) = 34 bytes
        let binxml_start = start + 34;
        let length = u32::from_le_bytes(chunk[start+30..start+34].try_into().unwrap()) as usize;
        println!("Template 0x226: 0x0C at 0x{start:X}, BinXml at 0x{binxml_start:X}, length={length}");
        // Show first 128 bytes of BinXml as hex
        let end = (binxml_start + length).min(binxml_start + 200);
        for i in (binxml_start..end).step_by(16) {
            let row_end = (i + 16).min(end);
            let hex: Vec<String> = chunk[i..row_end].iter().map(|b| format!("{b:02X}")).collect();
            println!("  0x{i:04X}: {}", hex.join(" "));
        }
        // Also dump substitutions of record 1
        let records_start = 0x80usize + 0x100 + 0x80; // table_offset(0x80) + 0x180
        let mut pos = records_start;
        let mut strings = build_string_table(chunk, 0x80);
        let templates = parse_templates(chunk, &mut strings);
        let rec_size = u32::from_le_bytes(chunk[pos+4..pos+8].try_into().unwrap()) as usize;
        println!("Record 1 at 0x{pos:X}, size={rec_size}");
        let payload = &chunk[pos+24..pos+rec_size];
        for i in (0..payload.len().min(100)).step_by(16) {
            let row_end = (i+16).min(payload.len().min(100));
            let hex: Vec<String> = payload[i..row_end].iter().map(|b| format!("{b:02X}")).collect();
            println!("  payload+0x{i:04X}: {}", hex.join(" "));
        }
        // Show all subs for record 1
        if let Some((toff, subs)) = parse_record_payload(chunk, pos+24, pos, &templates, &mut strings) {
            println!("  template_offset=0x{toff:X}, {} subs", subs.len());
            for (i, s) in subs.iter().enumerate() {
                let preview: String = s.data.iter().take(8).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
                println!("  sub[{i}]: vtype=0x{:02X} size={} data=[{preview}]", s.vtype, s.size);
            }
        }
    }

    /// Parse the bundled Sysmon .evtx file and verify we get events.
    /// Requires `evtx/Microsoft-Windows-Sysmon%4Operational.evtx` relative to workspace root.
    #[test]
    fn parse_real_evtx_file() {
        // Locate the test file relative to the workspace root (two levels up from crate)
        let path = evtx_path();
        if !path.exists() {
            eprintln!("Skipping test: evtx test file not found at {}", path.display());
            return;
        }
        let evtx_path = path;

        let (tx, rx) = crossbeam_channel::unbounded();
        let bytes = Arc::new(AtomicU64::new(0));
        let mut errors = Vec::new();
        let rodeo = crate::new_rodeo();

        let result = parse_evtx_file(&evtx_path, &tx, &bytes, &mut errors, &rodeo);
        drop(tx);

        assert!(result.is_ok(), "parse_evtx_file returned error: {:?}", result);

        let mut total = 0usize;
        let mut by_id: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
        while let Ok(batch) = rx.recv() {
            for ev in &batch {
                total += 1;
                *by_id.entry(ev.event_id).or_insert(0) += 1;
            }
        }

        assert!(total > 0, "Expected at least one event, got 0");
        println!("Parsed {total} Sysmon events");
        for (id, count) in &by_id {
            println!("  EventId {id}: {count}");
        }
        if !errors.is_empty() {
            println!("{} parse errors", errors.len());
        }
    }

    /// Print fields for the first event to verify against sysmon2.json record 1.
    #[test]
    fn verify_record1_fields() {
        let path = evtx_path();
        if !path.exists() { return; }

        let (tx, rx) = crossbeam_channel::unbounded();
        let bytes = Arc::new(AtomicU64::new(0));
        let mut errors = Vec::new();
        let rodeo = crate::new_rodeo();
        let _ = parse_evtx_file(&path, &tx, &bytes, &mut errors, &rodeo);
        drop(tx);

        // Collect all events, find record_number == 1
        let mut all: Vec<crate::event::SysmonEvent> = Vec::new();
        while let Ok(batch) = rx.recv() { all.extend(batch); }
        all.sort_by_key(|e| e.record_number);

        if let Some(ev) = all.first() {
            println!("Record 1: event_id={}, time={}", ev.event_id, ev.time_created);
            println!("  computer: {}", rodeo.resolve(&ev.computer));
            println!("  image: {:?}", ev.image.map(|k| rodeo.resolve(&k)));
            println!("  process_guid: {:?}", ev.process_guid);
            println!("  detail: {:?}", ev.detail);
        }
    }
}
