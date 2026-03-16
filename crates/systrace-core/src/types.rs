use thiserror::Error;

/// Unique process identifier: 128-bit compact representation of a Sysmon ProcessGuid.
/// Format on the wire: "817bddf3-3514-65cc-0802-000000001900" (standard GUID string)
pub type ProcessGuid = [u8; 16];

/// Parsed UTC timestamp.
pub type Timestamp = chrono::DateTime<chrono::Utc>;

/// A MITRE ATT&CK technique parsed from the Sysmon RuleName field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitreTechnique {
    /// e.g. "T1189"
    pub id: String,
    /// e.g. "Drive-by Compromise"
    pub name: String,
}

/// Errors produced during NDJSON parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line {line}: failed to deserialize top-level record: {source}")]
    TopLevelDeserialize {
        line: u64,
        #[source]
        source: serde_json::Error,
    },

    #[error("line {line}: failed to parse Payload JSON: {source}")]
    PayloadDeserialize {
        line: u64,
        #[source]
        source: serde_json::Error,
    },

    #[error("line {line}: missing required field '{field}'")]
    MissingField { line: u64, field: &'static str },

    #[error("line {line}: invalid GUID '{guid}': {source}")]
    InvalidGuid {
        line: u64,
        guid: String,
        #[source]
        source: uuid::Error,
    },

    #[error("line {line}: invalid timestamp '{value}': {source}")]
    InvalidTimestamp {
        line: u64,
        value: String,
        #[source]
        source: chrono::ParseError,
    },

    #[error("csv row {line}: {message}")]
    CsvRowError { line: u64, message: String },
}

/// Parse a Sysmon GUID string ("817bddf3-3514-65cc-0802-000000001900") into 16 bytes.
pub fn parse_guid(s: &str) -> Result<ProcessGuid, uuid::Error> {
    let uuid = uuid::Uuid::parse_str(s)?;
    Ok(*uuid.as_bytes())
}

/// Try parsing a Sysmon GUID; returns `None` on empty/missing values without error.
pub fn parse_guid_opt(s: &str) -> Result<Option<ProcessGuid>, uuid::Error> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return Ok(None);
    }
    let guid = parse_guid(trimmed)?;
    // Sysmon uses the all-zeros GUID as a null sentinel (parent not available)
    if guid == [0u8; 16] {
        return Ok(None);
    }
    Ok(Some(guid))
}

/// Parse a MITRE technique reference from RuleName.
/// Expected format: `technique_id=T1189,technique_name=Drive-by Compromise`
pub fn parse_mitre_rule_name(rule_name: &str) -> Option<MitreTechnique> {
    if rule_name.is_empty() || rule_name == "-" {
        return None;
    }
    let mut id = None;
    let mut name = None;
    for part in rule_name.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("technique_id=") {
            id = Some(val.trim().to_owned());
        } else if let Some(val) = part.strip_prefix("technique_name=") {
            name = Some(val.trim().to_owned());
        }
    }
    match (id, name) {
        (Some(id), Some(name)) => Some(MitreTechnique { id, name }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_guid_roundtrip() {
        let s = "817bddf3-3514-65cc-0802-000000001900";
        let bytes = parse_guid(s).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn parse_guid_invalid() {
        assert!(parse_guid("not-a-guid").is_err());
    }

    #[test]
    fn parse_guid_opt_empty() {
        assert_eq!(parse_guid_opt("").unwrap(), None);
        assert_eq!(parse_guid_opt("-").unwrap(), None);
    }

    #[test]
    fn parse_guid_opt_all_zeros_is_none() {
        // Sysmon uses all-zeros GUID as null sentinel
        assert_eq!(parse_guid_opt("00000000-0000-0000-0000-000000000000").unwrap(), None);
        assert_eq!(parse_guid_opt("{00000000-0000-0000-0000-000000000000}").unwrap(), None);
    }

    #[test]
    fn parse_mitre_full() {
        let t = parse_mitre_rule_name(
            "technique_id=T1189,technique_name=Drive-by Compromise",
        )
        .unwrap();
        assert_eq!(t.id, "T1189");
        assert_eq!(t.name, "Drive-by Compromise");
    }

    #[test]
    fn parse_mitre_empty() {
        assert!(parse_mitre_rule_name("").is_none());
        assert!(parse_mitre_rule_name("-").is_none());
        assert!(parse_mitre_rule_name("no_technique_here").is_none());
    }
}
