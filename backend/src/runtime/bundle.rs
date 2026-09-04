//! Portable Vortex Runtime Policy Bundle.
//!
//! A bundle is a distribution artifact around `RuntimePolicy`.
//! Enforcement semantics remain owned by the runtime policy and validator.

use crate::runtime::RuntimePolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VORTEX_POLICY_API_VERSION: &str = "vortex.okamoto.dev/v1alpha1";
pub const VORTEX_POLICY_KIND: &str = "RuntimePolicyBundle";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleMetadata {
    pub name: String,
    pub version: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleIntegrity {
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VortexPolicyBundle {
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyBundleMetadata,
    pub policy: RuntimePolicy,

    #[serde(default)]
    pub integrity: Option<PolicyBundleIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBundleError {
    UnsupportedApiVersion(String),
    InvalidKind(String),
    EmptyName,
    EmptyVersion,
    MetadataPolicyVersionMismatch {
        metadata_version: String,
        policy_version: String,
    },
    UnsupportedIntegrityAlgorithm(String),
    IntegrityMismatch,
    Serialization(String),
}

impl VortexPolicyBundle {
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        author: Option<String>,
        policy: RuntimePolicy,
    ) -> Self {
        Self {
            api_version: VORTEX_POLICY_API_VERSION.to_string(),
            kind: VORTEX_POLICY_KIND.to_string(),
            metadata: PolicyBundleMetadata {
                name: name.into(),
                version: policy.version.clone(),
                description,
                author,
            },
            policy,
            integrity: None,
        }
    }

    pub fn validate(&self) -> Result<(), PolicyBundleError> {
        if self.api_version != VORTEX_POLICY_API_VERSION {
            return Err(PolicyBundleError::UnsupportedApiVersion(
                self.api_version.clone(),
            ));
        }

        if self.kind != VORTEX_POLICY_KIND {
            return Err(PolicyBundleError::InvalidKind(self.kind.clone()));
        }

        if self.metadata.name.trim().is_empty() {
            return Err(PolicyBundleError::EmptyName);
        }

        if self.metadata.version.trim().is_empty() {
            return Err(PolicyBundleError::EmptyVersion);
        }

        if self.metadata.version != self.policy.version {
            return Err(PolicyBundleError::MetadataPolicyVersionMismatch {
                metadata_version: self.metadata.version.clone(),
                policy_version: self.policy.version.clone(),
            });
        }

        if let Some(integrity) = &self.integrity {
            if integrity.algorithm != "sha256" {
                return Err(PolicyBundleError::UnsupportedIntegrityAlgorithm(
                    integrity.algorithm.clone(),
                ));
            }

            let expected = self.compute_digest()?;

            if integrity.digest != expected {
                return Err(PolicyBundleError::IntegrityMismatch);
            }
        }

        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, PolicyBundleError> {
        let canonical = self.canonical_payload()?;

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    pub fn seal(mut self) -> Result<Self, PolicyBundleError> {
        let digest = self.compute_digest()?;

        self.integrity = Some(PolicyBundleIntegrity {
            algorithm: "sha256".to_string(),
            digest,
        });

        Ok(self)
    }

    fn canonical_payload(&self) -> Result<String, PolicyBundleError> {
        #[derive(Serialize)]
        struct DigestPayload<'a> {
            api_version: &'a str,
            kind: &'a str,
            metadata: &'a PolicyBundleMetadata,
            policy: &'a RuntimePolicy,
        }

        serde_json::to_string(&DigestPayload {
            api_version: &self.api_version,
            kind: &self.kind,
            metadata: &self.metadata,
            policy: &self.policy,
        })
        .map_err(|error| PolicyBundleError::Serialization(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Operation, RuntimePolicy};

    fn test_bundle() -> VortexPolicyBundle {
        let policy = RuntimePolicy::new("runtime.agent.tool_execution", "0.1.0")
            .allow_operation(Operation::Anonymize)
            .with_identity_requirement(true)
            .with_required_scope("agent:execute")
            .with_fail_closed(true);

        VortexPolicyBundle::new(
            "agent-tool-execution",
            Some("Example portable Vortex policy bundle.".to_string()),
            Some("Okamoto Security Labs".to_string()),
            policy,
        )
    }

    #[test]
    fn valid_bundle_passes_validation() {
        let bundle = test_bundle();

        assert_eq!(bundle.validate(), Ok(()));
    }

    #[test]
    fn sealed_bundle_passes_integrity_validation() {
        let bundle = test_bundle().seal().expect("bundle should seal");

        assert!(bundle.integrity.is_some());
        assert_eq!(bundle.validate(), Ok(()));
    }

    #[test]
    fn tampered_bundle_fails_integrity_validation() {
        let mut bundle = test_bundle().seal().expect("bundle should seal");

        bundle.metadata.name = "tampered".to_string();

        assert_eq!(bundle.validate(), Err(PolicyBundleError::IntegrityMismatch));
    }

    #[test]
    fn metadata_version_must_match_policy_version() {
        let mut bundle = test_bundle();

        bundle.metadata.version = "9.9.9".to_string();

        assert_eq!(
            bundle.validate(),
            Err(PolicyBundleError::MetadataPolicyVersionMismatch {
                metadata_version: "9.9.9".to_string(),
                policy_version: "0.1.0".to_string(),
            })
        );
    }

    #[test]
    fn digest_is_deterministic() {
        let first = test_bundle().compute_digest().expect("digest");
        let second = test_bundle().compute_digest().expect("digest");

        assert_eq!(first, second);
    }

    #[test]
    fn bundle_json_round_trip_preserves_semantics() {
        let bundle = test_bundle().seal().expect("bundle should seal");

        let json = serde_json::to_string_pretty(&bundle).expect("serialize bundle");

        let decoded: VortexPolicyBundle = serde_json::from_str(&json).expect("deserialize bundle");

        assert_eq!(decoded, bundle);
        assert_eq!(decoded.validate(), Ok(()));
    }

    #[test]
    fn fixture_bundle_parses_and_validates() {
        let fixture =
            include_str!("../../../registry/policies/agents/tool-execution/0.1.0/policy.json");

        let bundle: VortexPolicyBundle =
            serde_json::from_str(fixture).expect("fixture should parse");

        assert_eq!(bundle.metadata.name, "agent-tool-execution");
        assert_eq!(bundle.policy.id, "runtime.agent.tool_execution");
        assert_eq!(bundle.validate(), Ok(()));
    }
}
