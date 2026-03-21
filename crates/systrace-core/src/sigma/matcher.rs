//! Sigma rule evaluation engine against EventStore events.

use std::collections::HashMap;
use regex::Regex;

use crate::{EventDetail, EventStore, ProcessGuid, SharedRodeo, SysmonEvent, Timestamp};
use super::rule::{ConditionExpr, Modifier, SigmaDetection, SigmaFieldMatch, SigmaLevel, SigmaRule, SigmaSelection};

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SigmaMatch {
    pub rule_title:   String,
    pub rule_id:      Option<String>,
    pub level:        SigmaLevel,
    pub event_index:  usize,
    pub event_id:     u16,
    pub process_guid: Option<ProcessGuid>,
    pub timestamp:    Timestamp,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate all rules against all events in the store. Returns every match found.
pub fn evaluate_rules(
    rules: &[SigmaRule],
    event_store: &EventStore,
    rodeo: &SharedRodeo,
) -> Vec<SigmaMatch> {
    let mut results = Vec::new();

    for rule in rules {
        let event_ids = super::category_to_event_ids(rule.logsource.category.as_deref());
        if event_ids.is_empty() {
            continue;
        }

        for &eid in event_ids {
            let indices = event_store.events_for_type(eid);
            for &idx in indices {
                let event = &event_store.events[idx];
                if matches_rule(rule, event, rodeo) {
                    results.push(SigmaMatch {
                        rule_title:   rule.title.clone(),
                        rule_id:      rule.id.clone(),
                        level:        rule.level,
                        event_index:  idx,
                        event_id:     event.event_id,
                        process_guid: event.process_guid,
                        timestamp:    event.time_created,
                    });
                }
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Rule evaluation
// ---------------------------------------------------------------------------

fn matches_rule(rule: &SigmaRule, event: &SysmonEvent, rodeo: &SharedRodeo) -> bool {
    // Evaluate each selection: true if ALL fields in the selection match.
    let sel_results: HashMap<&str, bool> = rule
        .detection
        .selections
        .iter()
        .map(|(name, sel)| (name.as_str(), selection_matches(sel, event, rodeo)))
        .collect();

    eval_condition(&rule.detection.condition, &sel_results, &rule.detection)
}

fn eval_condition(
    expr: &ConditionExpr,
    sel_results: &HashMap<&str, bool>,
    detection: &SigmaDetection,
) -> bool {
    match expr {
        ConditionExpr::Named(name) => {
            *sel_results.get(name.as_str()).unwrap_or(&false)
        }
        ConditionExpr::Not(inner) => !eval_condition(inner, sel_results, detection),
        ConditionExpr::And(parts) => {
            parts.iter().all(|p| eval_condition(p, sel_results, detection))
        }
        ConditionExpr::Or(parts) => {
            parts.iter().any(|p| eval_condition(p, sel_results, detection))
        }
        ConditionExpr::OneOf(pattern) => {
            // At least one selection whose name matches the glob pattern is true.
            let pat = glob_to_regex(pattern);
            sel_results
                .iter()
                .any(|(name, &matched)| matched && pat.is_match(name))
        }
        ConditionExpr::AllOf(pattern) => {
            // All selections whose name matches the glob pattern must be true.
            let pat = glob_to_regex(pattern);
            let matching: Vec<bool> = sel_results
                .iter()
                .filter(|(name, _)| pat.is_match(name))
                .map(|(_, &v)| v)
                .collect();
            !matching.is_empty() && matching.iter().all(|&v| v)
        }
    }
}

/// Simple glob→regex converter (only handles `*` wildcard).
fn glob_to_regex(pattern: &str) -> Regex {
    let escaped = regex::escape(pattern).replace(r"\*", ".*");
    Regex::new(&format!("^{escaped}$")).unwrap_or_else(|_| Regex::new("(?!)").unwrap())
}

// ---------------------------------------------------------------------------
// Selection evaluation
// ---------------------------------------------------------------------------

fn selection_matches(sel: &SigmaSelection, event: &SysmonEvent, rodeo: &SharedRodeo) -> bool {
    // All fields must match (AND logic).
    sel.fields.iter().all(|fm| field_match(fm, event, rodeo))
}

fn field_match(fm: &SigmaFieldMatch, event: &SysmonEvent, rodeo: &SharedRodeo) -> bool {
    if fm.values.is_empty() {
        return true;
    }

    let value = match get_field_value(event, &fm.field, rodeo) {
        Some(v) => v,
        None => return false,
    };

    let has_all = fm.modifiers.contains(&Modifier::All);

    if has_all {
        // All values must match (AND).
        fm.values.iter().all(|pattern| apply_modifiers(&fm.modifiers, &value, pattern))
    } else {
        // Any value must match (OR).
        fm.values.iter().any(|pattern| apply_modifiers(&fm.modifiers, &value, pattern))
    }
}

fn apply_modifiers(modifiers: &[Modifier], value: &str, pattern: &str) -> bool {
    let v_lower = value.to_lowercase();
    let p_lower = pattern.to_lowercase();

    if modifiers.contains(&Modifier::Re) {
        // Regex match (case-sensitive as specified in pattern).
        return Regex::new(pattern).map(|re| re.is_match(value)).unwrap_or(false);
    }

    if modifiers.contains(&Modifier::Contains) {
        return v_lower.contains(&p_lower);
    }
    if modifiers.contains(&Modifier::StartsWith) {
        return v_lower.starts_with(&p_lower);
    }
    if modifiers.contains(&Modifier::EndsWith) {
        return v_lower.ends_with(&p_lower);
    }

    // No directional modifier: exact case-insensitive match.
    v_lower == p_lower
}

// ---------------------------------------------------------------------------
// Field value extraction per EventDetail variant
// ---------------------------------------------------------------------------

fn get_field_value(event: &SysmonEvent, field: &str, rodeo: &SharedRodeo) -> Option<String> {
    // Common fields available on all events.
    match field {
        "Image" => {
            return event.image.map(|s| rodeo.resolve(&s).to_owned());
        }
        "User" => {
            return event.user.map(|s| rodeo.resolve(&s).to_owned());
        }
        "Computer" => {
            return Some(rodeo.resolve(&event.computer).to_owned());
        }
        "RuleName" => {
            return event.rule_name.clone();
        }
        _ => {}
    }

    // Type-specific fields.
    match &event.detail {
        EventDetail::ProcessCreate {
            command_line,
            current_directory,
            hashes,
            parent_image,
            parent_command_line,
            parent_user,
            integrity_level,
            file_version,
            description,
            product,
            company,
            original_file_name,
            ..
        } => match field {
            "CommandLine"         => command_line.clone(),
            "CurrentDirectory"    => current_directory.clone(),
            "Hashes"              => hashes.clone(),
            "ParentImage"         => parent_image.clone(),
            "ParentCommandLine"   => parent_command_line.clone(),
            "ParentUser"          => parent_user.clone(),
            "IntegrityLevel"      => integrity_level.clone(),
            "FileVersion"         => file_version.clone(),
            "Description"         => description.clone(),
            "Product"             => product.clone(),
            "Company"             => company.clone(),
            "OriginalFileName"    => original_file_name.clone(),
            _ => None,
        },

        EventDetail::NetworkConnect {
            protocol,
            source_ip,
            source_hostname,
            destination_ip,
            destination_hostname,
            source_port,
            destination_port,
            initiated,
        } => match field {
            "Protocol"             => protocol.clone(),
            "SourceIp"             => source_ip.clone(),
            "SourceHostname"       => source_hostname.clone(),
            "DestinationIp"        => destination_ip.clone(),
            "DestinationHostname"  => destination_hostname.clone(),
            "SourcePort"           => source_port.map(|p| p.to_string()),
            "DestinationPort"      => destination_port.map(|p| p.to_string()),
            "Initiated"            => initiated.map(|b| b.to_string()),
            _ => None,
        },

        EventDetail::ProcessAccess {
            source_image,
            target_image,
            granted_access,
            call_trace,
            ..
        } => match field {
            "SourceImage"    => source_image.clone(),
            "TargetImage"    => target_image.clone(),
            "GrantedAccess"  => granted_access.clone(),
            "CallTrace"      => call_trace.clone(),
            _ => None,
        },

        EventDetail::CreateRemoteThread {
            source_image,
            target_image,
            start_address,
            start_module,
            start_function,
            ..
        } => match field {
            "SourceImage"     => source_image.clone(),
            "TargetImage"     => target_image.clone(),
            "StartAddress"    => start_address.clone(),
            "StartModule"     => start_module.clone(),
            "StartFunction"   => start_function.clone(),
            _ => None,
        },

        EventDetail::FileCreate { target_filename, .. } |
        EventDetail::FileCreateStreamHash { target_filename, .. } |
        EventDetail::FileCreateTime { target_filename, .. } => match field {
            "TargetFilename" => target_filename.clone(),
            _ => None,
        },

        EventDetail::FileDeleteEvent { target_filename, hashes, is_executable } => match field {
            "TargetFilename"  => target_filename.clone(),
            "Hashes"          => hashes.clone(),
            "IsExecutable"    => is_executable.map(|b| b.to_string()),
            _ => None,
        },

        EventDetail::RegistryEvent { event_type, target_object, details, new_name } => match field {
            "EventType"    => event_type.clone(),
            "TargetObject" => target_object.clone(),
            "Details"      => details.clone(),
            "NewName"      => new_name.clone(),
            _ => None,
        },

        EventDetail::DnsQuery { query_name, query_status, query_results } => match field {
            "QueryName"    => query_name.clone(),
            "QueryStatus"  => query_status.clone(),
            "QueryResults" => query_results.clone(),
            _ => None,
        },

        EventDetail::PipeEvent { pipe_name, event_type } => match field {
            "PipeName"  => pipe_name.clone(),
            "EventType" => Some(event_type.clone()),
            _ => None,
        },

        EventDetail::DriverLoad { image_loaded, hashes, signature, signature_status } |
        EventDetail::ImageLoad { image_loaded, hashes, signature, signature_status, .. } => match field {
            "ImageLoaded"       => image_loaded.clone(),
            "Hashes"            => hashes.clone(),
            "Signature"         => signature.clone(),
            "SignatureStatus"    => signature_status.clone(),
            _ => None,
        },

        EventDetail::ProcessTampering { tampering_type } => match field {
            "Type" => tampering_type.clone(),
            _ => None,
        },

        EventDetail::ClipboardChange { session, client_info, hashes } => match field {
            "Session"    => session.clone(),
            "ClientInfo" => client_info.clone(),
            "Hashes"     => hashes.clone(),
            _ => None,
        },

        EventDetail::RawAccessRead { device } => match field {
            "Device" => device.clone(),
            _ => None,
        },

        EventDetail::WmiActivity { event_type, operation, name, query, .. } => match field {
            "EventType" => Some(event_type.clone()),
            "Operation" => operation.clone(),
            "Name"      => name.clone(),
            "Query"     => query.clone(),
            _ => None,
        },

        EventDetail::Generic { fields } => fields.get(field).cloned(),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventDetail, SysmonEvent, SysmonEventType};
    use crate::event_store::EventStore;
    use crate::types::parse_guid;
    use crate::new_rodeo;
    use chrono::Utc;

    fn make_process_create_event(
        image: &str,
        command_line: &str,
        rodeo: &SharedRodeo,
    ) -> SysmonEvent {
        let img_spur = rodeo.get_or_intern(image);
        SysmonEvent {
            event_id: 1,
            event_type: SysmonEventType::ProcessCreate,
            time_created: Utc::now(),
            record_number: 1,
            computer: rodeo.get_or_intern("TESTHOST"),
            process_guid: Some(parse_guid("00000000-0000-0000-0000-000000000001").unwrap()),
            process_id: Some(1234),
            image: Some(img_spur),
            user: None,
            rule_name: None,
            mitre_technique: None,
            detail: EventDetail::ProcessCreate {
                command_line: Some(command_line.to_owned()),
                current_directory: None,
                hashes: None,
                parent_process_guid: None,
                parent_process_id: None,
                parent_image: None,
                parent_command_line: None,
                parent_user: None,
                logon_guid: None,
                logon_id: None,
                terminal_session_id: None,
                integrity_level: None,
                file_version: None,
                description: None,
                product: None,
                company: None,
                original_file_name: None,
            },
        }
    }

    const LSASS_RULE_YAML: &str = r#"
title: LSASS Memory Dump via comsvcs.dll MiniDump
id: 5f0b4c16-85c0-4f73-bce9-2d0a5b1c3e7f
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - comsvcs
      - MiniDump
  condition: selection
level: critical
"#;

    const PS_B64_RULE_YAML: &str = r#"
title: PowerShell Base64 Encoded Command Execution
id: 7b2d94c5-3f81-4e29-b3d7-a8e6f5c2d4b1
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_cmd:
    CommandLine|contains:
      - ' -e '
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
  condition: selection_img and selection_cmd
level: high
"#;

    #[test]
    fn lsass_dump_rule_matches() {
        let rodeo = new_rodeo();
        let mut store = EventStore::new();

        // Matching event: command line contains comsvcs + MiniDump (as seen in CSV sample)
        let event = make_process_create_event(
            r"C:\Windows\system32\cmd.exe",
            r"cmd.exe /c rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full",
            &rodeo,
        );
        store.insert(event);

        let rule = SigmaRule::from_yaml(LSASS_RULE_YAML).unwrap();
        let matches = evaluate_rules(&[rule], &store, &rodeo);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].event_id, 1);
    }

    #[test]
    fn lsass_dump_rule_no_match() {
        let rodeo = new_rodeo();
        let mut store = EventStore::new();

        let event = make_process_create_event(
            r"C:\Windows\System32\cmd.exe",
            r"cmd.exe /c dir",
            &rodeo,
        );
        store.insert(event);

        let rule = SigmaRule::from_yaml(LSASS_RULE_YAML).unwrap();
        let matches = evaluate_rules(&[rule], &store, &rodeo);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn ps_b64_rule_matches() {
        let rodeo = new_rodeo();
        let mut store = EventStore::new();

        // Matching: -e flag as seen in CSV sample data
        let event = make_process_create_event(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell.exe -e JABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwA=",
            &rodeo,
        );
        store.insert(event);

        let rule = SigmaRule::from_yaml(PS_B64_RULE_YAML).unwrap();
        let matches = evaluate_rules(&[rule], &store, &rodeo);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn modifier_contains_case_insensitive() {
        let fm = SigmaFieldMatch {
            field: "CommandLine".to_owned(),
            modifiers: vec![Modifier::Contains],
            values: vec!["COMSVCS".to_owned()],
        };
        let rodeo = new_rodeo();
        let event = make_process_create_event(
            r"C:\Windows\System32\rundll32.exe",
            r"rundll32.exe comsvcs.dll MiniDump",
            &rodeo,
        );
        assert!(field_match(&fm, &event, &rodeo));
    }

    #[test]
    fn modifier_endswith() {
        let fm = SigmaFieldMatch {
            field: "Image".to_owned(),
            modifiers: vec![Modifier::EndsWith],
            values: vec![r"\rundll32.exe".to_owned()],
        };
        let rodeo = new_rodeo();
        let event = make_process_create_event(
            r"C:\Windows\System32\rundll32.exe",
            "test",
            &rodeo,
        );
        assert!(field_match(&fm, &event, &rodeo));
    }
}
