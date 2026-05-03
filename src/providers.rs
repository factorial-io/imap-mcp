//! IMAP provider allowlist.
//!
//! The server only logs into IMAP hosts that appear in this allowlist.
//! Operators load it from `IMAP_PROVIDERS` (JSON list) or
//! `--imap-providers <path-or-json>` (CLI flag, wins over env). The default
//! list contains exactly one entry: `mail.factorial.io`. Anything else is
//! opt-in by the operator at deploy time.

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapProvider {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProviderList {
    providers: Vec<ImapProvider>,
}

impl ProviderList {
    pub fn new(providers: Vec<ImapProvider>) -> Result<Self, AppError> {
        if providers.is_empty() {
            return Err(AppError::Internal(
                "IMAP provider allowlist must contain at least one entry".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for p in &providers {
            if !seen.insert(&p.id) {
                return Err(AppError::Internal(format!(
                    "duplicate provider id in allowlist: {}",
                    p.id
                )));
            }
            if p.id.is_empty() || p.label.is_empty() || p.host.is_empty() {
                return Err(AppError::Internal(
                    "provider id, label, and host must be non-empty".into(),
                ));
            }
        }
        Ok(Self { providers })
    }

    /// Default ships only with mail.factorial.io. Operators opt non-Factorial
    /// providers in via env or CLI.
    pub fn factorial_default(host: &str, port: u16) -> Result<Self, AppError> {
        Self::new(vec![ImapProvider {
            id: "factorial".to_string(),
            label: "Factorial".to_string(),
            host: host.to_string(),
            port,
            note: None,
        }])
    }

    /// Parse from JSON. Accepts either a raw JSON list or a path to a file
    /// containing one. Distinguished by leading `[` (list) vs anything else
    /// (path).
    pub fn parse_inline_or_path(raw: &str) -> Result<Self, AppError> {
        let trimmed = raw.trim();
        let json = if trimmed.starts_with('[') {
            trimmed.to_string()
        } else {
            std::fs::read_to_string(trimmed).map_err(|e| {
                AppError::Internal(format!("failed to read providers file '{trimmed}': {e}"))
            })?
        };
        let list: Vec<ImapProvider> = serde_json::from_str(&json)
            .map_err(|e| AppError::Internal(format!("invalid IMAP_PROVIDERS JSON: {e}")))?;
        Self::new(list)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ImapProvider> {
        self.providers.iter()
    }

    pub fn get(&self, id: &str) -> Option<&ImapProvider> {
        self.providers.iter().find(|p| p.id == id)
    }

    pub fn get_by_host(&self, host: &str, port: u16) -> Option<&ImapProvider> {
        self.providers
            .iter()
            .find(|p| p.host == host && p.port == port)
    }

    pub fn first(&self) -> &ImapProvider {
        // Safety: ::new rejects empty lists.
        &self.providers[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factorial_default_has_one_entry() {
        let list = ProviderList::factorial_default("mail.factorial.io", 993).unwrap();
        let entries: Vec<&ImapProvider> = list.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "factorial");
        assert_eq!(entries[0].host, "mail.factorial.io");
        assert_eq!(entries[0].port, 993);
    }

    #[test]
    fn parse_inline_json() {
        let raw = r#"[
            {"id":"factorial","label":"Factorial","host":"mail.factorial.io","port":993},
            {"id":"gmail","label":"Gmail","host":"imap.gmail.com","port":993,"note":"Use an app password"}
        ]"#;
        let list = ProviderList::parse_inline_or_path(raw).unwrap();
        assert_eq!(list.iter().count(), 2);
        assert_eq!(list.get("gmail").unwrap().host, "imap.gmail.com");
        assert_eq!(
            list.get("gmail").unwrap().note.as_deref(),
            Some("Use an app password")
        );
    }

    #[test]
    fn rejects_empty_list() {
        let raw = "[]";
        assert!(ProviderList::parse_inline_or_path(raw).is_err());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let raw = r#"[
            {"id":"x","label":"A","host":"a","port":993},
            {"id":"x","label":"B","host":"b","port":993}
        ]"#;
        let err = ProviderList::parse_inline_or_path(raw).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_missing_fields() {
        let raw = r#"[{"id":"x","label":"","host":"h","port":993}]"#;
        assert!(ProviderList::parse_inline_or_path(raw).is_err());
    }

    #[test]
    fn get_by_host_finds_match() {
        let list = ProviderList::factorial_default("mail.factorial.io", 993).unwrap();
        assert!(list.get_by_host("mail.factorial.io", 993).is_some());
        assert!(list.get_by_host("mail.factorial.io", 143).is_none());
        assert!(list.get_by_host("imap.gmail.com", 993).is_none());
    }
}
