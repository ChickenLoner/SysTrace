//! Sigma rule data structures, YAML deserialization, and condition parsing.

use std::collections::HashMap;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigmaLevel {
    Informational,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl SigmaLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Informational => "Info",
            Self::Low           => "Low",
            Self::Medium        => "Medium",
            Self::High          => "High",
            Self::Critical      => "Critical",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigmaLogsource {
    pub category: Option<String>,
    pub product:  Option<String>,
    pub service:  Option<String>,
}

/// A single field match: field name + modifiers + values to match against.
#[derive(Debug, Clone)]
pub struct SigmaFieldMatch {
    pub field:     String,
    pub modifiers: Vec<Modifier>,
    pub values:    Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    Re,
    All,
    // base64offset etc. can be added later
}

/// A named selection block: all fields must match (AND logic between fields).
#[derive(Debug, Clone)]
pub struct SigmaSelection {
    pub fields: Vec<SigmaFieldMatch>,
}

/// Parsed condition expression.
#[derive(Debug, Clone)]
pub enum ConditionExpr {
    /// Reference a named selection or filter, e.g. "selection".
    Named(String),
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    /// "1 of <pattern>" — at least one selection matching the glob pattern matches.
    OneOf(String),
    /// "all of <pattern>" — all selections matching the glob pattern match.
    AllOf(String),
}

#[derive(Debug, Clone)]
pub struct SigmaDetection {
    pub selections: HashMap<String, SigmaSelection>,
    pub condition:  ConditionExpr,
}

#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub title:       String,
    pub id:          Option<String>,
    pub description: Option<String>,
    pub status:      Option<String>,
    pub level:       SigmaLevel,
    pub logsource:   SigmaLogsource,
    pub detection:   SigmaDetection,
}

// ---------------------------------------------------------------------------
// YAML parsing
// ---------------------------------------------------------------------------

/// Raw serde representation of the detection block.
#[derive(Debug, Deserialize)]
struct RawDetection {
    condition: String,
    #[serde(flatten)]
    selections: HashMap<String, serde_yaml::Value>,
}

/// Intermediate serde representation of the full rule.
#[derive(Debug, Deserialize)]
struct RawRule {
    title:       String,
    id:          Option<String>,
    description: Option<String>,
    status:      Option<String>,
    level:       Option<SigmaLevel>,
    logsource:   SigmaLogsource,
    detection:   RawDetection,
}

impl SigmaRule {
    pub fn from_yaml(yaml: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let raw: RawRule = serde_yaml::from_str(yaml)?;

        let mut selections = HashMap::new();
        for (key, val) in raw.detection.selections {
            if key == "condition" {
                continue; // already captured by RawDetection.condition
            }
            let selection = parse_selection(&val)?;
            selections.insert(key, selection);
        }

        let condition = parse_condition(&raw.detection.condition)?;

        Ok(SigmaRule {
            title:       raw.title,
            id:          raw.id,
            description: raw.description,
            status:      raw.status,
            level:       raw.level.unwrap_or_default(),
            logsource:   raw.logsource,
            detection:   SigmaDetection { selections, condition },
        })
    }
}

// ---------------------------------------------------------------------------
// Selection parsing
// ---------------------------------------------------------------------------

fn parse_selection(val: &serde_yaml::Value) -> Result<SigmaSelection, Box<dyn std::error::Error>> {
    let mut fields = Vec::new();

    match val {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key_str = k.as_str().ok_or("selection key must be a string")?;
                let (field, modifiers) = parse_field_key(key_str);
                let values = value_to_string_list(v)?;
                fields.push(SigmaFieldMatch { field, modifiers, values });
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            // List of string values (OR match on same field — treated as generic list filter)
            let values = seq
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            fields.push(SigmaFieldMatch {
                field:     String::new(),
                modifiers: Vec::new(),
                values,
            });
        }
        _ => {}
    }

    Ok(SigmaSelection { fields })
}

/// Parse a key like "CommandLine|contains|all" into (field, modifiers).
fn parse_field_key(key: &str) -> (String, Vec<Modifier>) {
    let parts: Vec<&str> = key.split('|').collect();
    let field = parts[0].to_owned();
    let modifiers = parts[1..]
        .iter()
        .filter_map(|m| match m.to_lowercase().as_str() {
            "contains"   => Some(Modifier::Contains),
            "startswith" => Some(Modifier::StartsWith),
            "endswith"   => Some(Modifier::EndsWith),
            "re"         => Some(Modifier::Re),
            "all"        => Some(Modifier::All),
            _            => None,
        })
        .collect();
    (field, modifiers)
}

fn value_to_string_list(val: &serde_yaml::Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match val {
        serde_yaml::Value::String(s) => Ok(vec![s.clone()]),
        serde_yaml::Value::Sequence(seq) => {
            let mut out = Vec::new();
            for v in seq {
                match v {
                    serde_yaml::Value::String(s) => out.push(s.clone()),
                    serde_yaml::Value::Number(n)  => out.push(n.to_string()),
                    _ => {}
                }
            }
            Ok(out)
        }
        serde_yaml::Value::Number(n) => Ok(vec![n.to_string()]),
        serde_yaml::Value::Bool(b)   => Ok(vec![b.to_string()]),
        _ => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Condition parsing
// ---------------------------------------------------------------------------

fn parse_condition(cond: &str) -> Result<ConditionExpr, Box<dyn std::error::Error>> {
    let tokens = tokenize(cond);
    let (expr, _) = parse_expr(&tokens, 0)?;
    Ok(expr)
}

fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '(' | ')' => {
                if !current.trim().is_empty() {
                    tokens.push(current.trim().to_owned());
                    current.clear();
                }
                tokens.push(ch.to_string());
            }
            ' ' | '\t' => {
                if !current.trim().is_empty() {
                    tokens.push(current.trim().to_owned());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        tokens.push(current.trim().to_owned());
    }
    tokens
}

/// Recursive descent parser for condition expressions.
/// Returns (expr, next_token_index).
fn parse_expr(tokens: &[String], pos: usize) -> Result<(ConditionExpr, usize), Box<dyn std::error::Error>> {
    let (mut lhs, mut pos) = parse_primary(tokens, pos)?;

    // Handle binary operators: and, or
    while pos < tokens.len() {
        match tokens[pos].to_lowercase().as_str() {
            "and" => {
                let (rhs, next) = parse_primary(tokens, pos + 1)?;
                lhs = flatten_and(lhs, rhs);
                pos = next;
            }
            "or" => {
                let (rhs, next) = parse_primary(tokens, pos + 1)?;
                lhs = flatten_or(lhs, rhs);
                pos = next;
            }
            ")" => break,
            _ => break,
        }
    }

    Ok((lhs, pos))
}

fn parse_primary(tokens: &[String], pos: usize) -> Result<(ConditionExpr, usize), Box<dyn std::error::Error>> {
    if pos >= tokens.len() {
        return Err("unexpected end of condition".into());
    }

    match tokens[pos].to_lowercase().as_str() {
        "not" => {
            let (inner, next) = parse_primary(tokens, pos + 1)?;
            Ok((ConditionExpr::Not(Box::new(inner)), next))
        }
        "(" => {
            let (inner, next) = parse_expr(tokens, pos + 1)?;
            let next = if next < tokens.len() && tokens[next] == ")" { next + 1 } else { next };
            Ok((inner, next))
        }
        "1" => {
            // "1 of <pattern>"
            if pos + 2 < tokens.len() && tokens[pos + 1].to_lowercase() == "of" {
                let pattern = tokens[pos + 2].clone();
                Ok((ConditionExpr::OneOf(pattern), pos + 3))
            } else {
                Err(format!("expected 'of <pattern>' after '1' at pos {}", pos).into())
            }
        }
        "all" => {
            // "all of <pattern>"
            if pos + 2 < tokens.len() && tokens[pos + 1].to_lowercase() == "of" {
                let pattern = tokens[pos + 2].clone();
                Ok((ConditionExpr::AllOf(pattern), pos + 3))
            } else {
                Err(format!("expected 'of <pattern>' after 'all' at pos {}", pos).into())
            }
        }
        _ => Ok((ConditionExpr::Named(tokens[pos].clone()), pos + 1)),
    }
}

fn flatten_and(lhs: ConditionExpr, rhs: ConditionExpr) -> ConditionExpr {
    match lhs {
        ConditionExpr::And(mut v) => { v.push(rhs); ConditionExpr::And(v) }
        other => ConditionExpr::And(vec![other, rhs]),
    }
}

fn flatten_or(lhs: ConditionExpr, rhs: ConditionExpr) -> ConditionExpr {
    match lhs {
        ConditionExpr::Or(mut v) => { v.push(rhs); ConditionExpr::Or(v) }
        other => ConditionExpr::Or(vec![other, rhs]),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const LSASS_RULE: &str = r#"
title: LSASS Memory Dump via comsvcs.dll
id: test-lsass-001
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - comsvcs
      - MiniDump
  condition: selection
level: critical
"#;

    const PS_B64_RULE: &str = r#"
title: PowerShell Encoded Command Execution
id: test-ps-b64-001
status: test
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
      - '-enc '
      - '-EncodedCommand'
      - '-ec '
  condition: selection_img and selection_cmd
level: high
"#;

    #[test]
    fn parse_lsass_rule() {
        let rule = SigmaRule::from_yaml(LSASS_RULE).unwrap();
        assert_eq!(rule.title, "LSASS Memory Dump via comsvcs.dll");
        assert_eq!(rule.level, SigmaLevel::Critical);
        assert_eq!(rule.logsource.category.as_deref(), Some("process_creation"));

        let sel = rule.detection.selections.get("selection").unwrap();
        assert_eq!(sel.fields.len(), 2);

        let image_field = sel.fields.iter().find(|f| f.field == "Image").unwrap();
        assert!(image_field.modifiers.contains(&Modifier::EndsWith));
        assert_eq!(image_field.values, vec![r"\rundll32.exe"]);

        let cmd_field = sel.fields.iter().find(|f| f.field == "CommandLine").unwrap();
        assert!(cmd_field.modifiers.contains(&Modifier::Contains));
        assert!(cmd_field.modifiers.contains(&Modifier::All));
        assert_eq!(cmd_field.values.len(), 2);
    }

    #[test]
    fn parse_ps_b64_rule() {
        let rule = SigmaRule::from_yaml(PS_B64_RULE).unwrap();
        assert_eq!(rule.level, SigmaLevel::High);
        assert!(rule.detection.selections.contains_key("selection_img"));
        assert!(rule.detection.selections.contains_key("selection_cmd"));

        // Condition should parse as And([Named("selection_img"), Named("selection_cmd")])
        match &rule.detection.condition {
            ConditionExpr::And(parts) => {
                assert_eq!(parts.len(), 2);
            }
            other => panic!("expected And condition, got {:?}", other),
        }
    }

    #[test]
    fn parse_field_key_modifiers() {
        let (field, mods) = parse_field_key("CommandLine|contains|all");
        assert_eq!(field, "CommandLine");
        assert_eq!(mods, vec![Modifier::Contains, Modifier::All]);

        let (field2, mods2) = parse_field_key("Image|endswith");
        assert_eq!(field2, "Image");
        assert_eq!(mods2, vec![Modifier::EndsWith]);

        let (field3, mods3) = parse_field_key("Image");
        assert_eq!(field3, "Image");
        assert!(mods3.is_empty());
    }
}
