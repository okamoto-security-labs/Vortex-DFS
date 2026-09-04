//! Portable registry discovery contract for Vortex policy bundles.
//!
//! The registry index is discovery metadata only.
//! It never grants authority to a policy bundle. Every downloaded bundle
//! must still pass its own runtime contract and integrity validation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::runtime::VORTEX_POLICY_API_VERSION;

pub const VORTEX_REGISTRY_INDEX_KIND: &str = "PolicyRegistryIndex";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRegistryEntry {
    pub namespace: String,
    pub name: String,
    pub latest: String,
    pub versions: Vec<String>,

    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRegistryIndex {
    pub api_version: String,
    pub kind: String,
    pub policies: Vec<PolicyRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryIndexError {
    UnsupportedApiVersion(String),
    InvalidKind(String),
    UnsafeIdentifier { field: &'static str, value: String },
    EmptyVersions { reference: String },
    LatestVersionMissing { reference: String, latest: String },
    DuplicateVersion { reference: String, version: String },
    DuplicatePolicy { reference: String },
}

impl PolicyRegistryEntry {
    pub fn reference(&self, version: &str) -> String {
        format!("{}/{}@{}", self.namespace, self.name, version)
    }

    pub fn latest_reference(&self) -> String {
        self.reference(&self.latest)
    }

    fn validate(&self) -> Result<(), RegistryIndexError> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("policy name", &self.name)?;
        validate_identifier("latest version", &self.latest)?;

        let reference = format!("{}/{}", self.namespace, self.name);

        if self.versions.is_empty() {
            return Err(RegistryIndexError::EmptyVersions { reference });
        }

        let mut seen = BTreeSet::new();

        for version in &self.versions {
            validate_identifier("version", version)?;

            if !seen.insert(version.clone()) {
                return Err(RegistryIndexError::DuplicateVersion {
                    reference: reference.clone(),
                    version: version.clone(),
                });
            }
        }

        if !seen.contains(&self.latest) {
            return Err(RegistryIndexError::LatestVersionMissing {
                reference,
                latest: self.latest.clone(),
            });
        }

        Ok(())
    }
}

impl PolicyRegistryIndex {
    pub fn validate(&self) -> Result<(), RegistryIndexError> {
        if self.api_version != VORTEX_POLICY_API_VERSION {
            return Err(RegistryIndexError::UnsupportedApiVersion(
                self.api_version.clone(),
            ));
        }

        if self.kind != VORTEX_REGISTRY_INDEX_KIND {
            return Err(RegistryIndexError::InvalidKind(self.kind.clone()));
        }

        let mut seen = BTreeSet::new();

        for policy in &self.policies {
            policy.validate()?;

            let reference = format!("{}/{}", policy.namespace, policy.name);

            if !seen.insert(reference.clone()) {
                return Err(RegistryIndexError::DuplicatePolicy { reference });
            }
        }

        Ok(())
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RegistryIndexError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

    if safe {
        Ok(())
    } else {
        Err(RegistryIndexError::UnsafeIdentifier {
            field,
            value: value.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_index() -> PolicyRegistryIndex {
        PolicyRegistryIndex {
            api_version: VORTEX_POLICY_API_VERSION.to_string(),
            kind: VORTEX_REGISTRY_INDEX_KIND.to_string(),
            policies: vec![PolicyRegistryEntry {
                namespace: "agents".to_string(),
                name: "tool-execution".to_string(),
                latest: "0.1.0".to_string(),
                versions: vec!["0.1.0".to_string()],
                description: Some("Guarded runtime policy for agent tool execution.".to_string()),
            }],
        }
    }

    #[test]
    fn valid_registry_index_passes_validation() {
        assert_eq!(valid_index().validate(), Ok(()));
    }

    #[test]
    fn latest_version_must_exist_in_versions() {
        let mut index = valid_index();
        index.policies[0].latest = "0.2.0".to_string();

        assert!(matches!(
            index.validate(),
            Err(RegistryIndexError::LatestVersionMissing { .. })
        ));
    }

    #[test]
    fn duplicate_version_is_rejected() {
        let mut index = valid_index();
        index.policies[0].versions.push("0.1.0".to_string());

        assert!(matches!(
            index.validate(),
            Err(RegistryIndexError::DuplicateVersion { .. })
        ));
    }

    #[test]
    fn duplicate_policy_is_rejected() {
        let mut index = valid_index();
        index.policies.push(index.policies[0].clone());

        assert!(matches!(
            index.validate(),
            Err(RegistryIndexError::DuplicatePolicy { .. })
        ));
    }

    #[test]
    fn unsafe_registry_identifier_is_rejected() {
        let mut index = valid_index();
        index.policies[0].namespace = "../escape".to_string();

        assert!(matches!(
            index.validate(),
            Err(RegistryIndexError::UnsafeIdentifier { .. })
        ));
    }

    #[test]
    fn fixture_registry_index_parses_and_validates() {
        let fixture = include_str!("../../registry/policies/index.json");

        let index: PolicyRegistryIndex =
            serde_json::from_str(fixture).expect("registry fixture should parse");

        assert_eq!(index.api_version, VORTEX_POLICY_API_VERSION);
        assert_eq!(index.kind, VORTEX_REGISTRY_INDEX_KIND);
        assert_eq!(index.policies.len(), 1);
        assert_eq!(
            index.policies[0].latest_reference(),
            "agents/tool-execution@0.1.0"
        );
        assert_eq!(index.validate(), Ok(()));
    }

    #[test]
    fn latest_reference_is_stable() {
        assert_eq!(
            valid_index().policies[0].latest_reference(),
            "agents/tool-execution@0.1.0"
        );
    }
}
