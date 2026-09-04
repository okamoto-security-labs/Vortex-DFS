//! Publisher identity and trust contracts for Vortex policy distribution.
//!
//! This module intentionally does not implement cryptographic verification yet.
//! It defines who signed, which key was referenced, and which publishers/keys
//! are trusted by the local runtime.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    pub namespace: String,
    pub publisher: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherSignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPublisher {
    pub namespace: String,
    pub publisher: String,
    pub keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublisherTrustStore {
    publishers: BTreeMap<String, TrustedPublisher>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherTrustError {
    UnsafeIdentifier { field: &'static str, value: String },
    DuplicatePublisher { reference: String },
    DuplicateKey { reference: String, key_id: String },
    PublisherNotTrusted { reference: String },
    KeyNotTrusted { reference: String, key_id: String },
}

impl PublisherIdentity {
    pub fn validate(&self) -> Result<(), PublisherTrustError> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("publisher", &self.publisher)?;
        validate_identifier("key id", &self.key_id)?;
        Ok(())
    }

    pub fn reference(&self) -> String {
        format!("{}/{}", self.namespace, self.publisher)
    }
}

impl TrustedPublisher {
    pub fn validate(&self) -> Result<(), PublisherTrustError> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("publisher", &self.publisher)?;

        let reference = format!("{}/{}", self.namespace, self.publisher);

        for key_id in self.keys.keys() {
            validate_identifier("key id", key_id)?;

            if key_id.is_empty() {
                return Err(PublisherTrustError::DuplicateKey {
                    reference: reference.clone(),
                    key_id: key_id.clone(),
                });
            }
        }

        Ok(())
    }

    pub fn reference(&self) -> String {
        format!("{}/{}", self.namespace, self.publisher)
    }
}

impl PublisherTrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, publisher: TrustedPublisher) -> Result<(), PublisherTrustError> {
        publisher.validate()?;

        let reference = publisher.reference();

        if self.publishers.contains_key(&reference) {
            return Err(PublisherTrustError::DuplicatePublisher { reference });
        }

        self.publishers.insert(reference, publisher);

        Ok(())
    }

    pub fn trusted_publisher(
        &self,
        namespace: &str,
        publisher: &str,
    ) -> Result<&TrustedPublisher, PublisherTrustError> {
        validate_identifier("namespace", namespace)?;
        validate_identifier("publisher", publisher)?;

        let reference = format!("{namespace}/{publisher}");

        self.publishers
            .get(&reference)
            .ok_or(PublisherTrustError::PublisherNotTrusted { reference })
    }

    pub fn trusted_key(&self, identity: &PublisherIdentity) -> Result<&str, PublisherTrustError> {
        identity.validate()?;

        let publisher = self.trusted_publisher(&identity.namespace, &identity.publisher)?;

        publisher
            .keys
            .get(&identity.key_id)
            .map(String::as_str)
            .ok_or_else(|| PublisherTrustError::KeyNotTrusted {
                reference: identity.reference(),
                key_id: identity.key_id.clone(),
            })
    }

    pub fn contains(&self, identity: &PublisherIdentity) -> Result<bool, PublisherTrustError> {
        match self.trusted_key(identity) {
            Ok(_) => Ok(true),
            Err(PublisherTrustError::PublisherNotTrusted { .. })
            | Err(PublisherTrustError::KeyNotTrusted { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), PublisherTrustError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

    if safe {
        Ok(())
    } else {
        Err(PublisherTrustError::UnsafeIdentifier {
            field,
            value: value.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_publisher() -> TrustedPublisher {
        TrustedPublisher {
            namespace: "okamoto".to_string(),
            publisher: "security-labs".to_string(),
            keys: BTreeMap::from([(
                "publisher-key-1".to_string(),
                "PUBLIC_KEY_PLACEHOLDER".to_string(),
            )]),
        }
    }

    #[test]
    fn valid_identity_passes_validation() {
        let identity = PublisherIdentity {
            namespace: "okamoto".to_string(),
            publisher: "security-labs".to_string(),
            key_id: "publisher-key-1".to_string(),
        };

        assert_eq!(identity.validate(), Ok(()));
    }

    #[test]
    fn unsafe_identity_is_rejected() {
        let identity = PublisherIdentity {
            namespace: "../escape".to_string(),
            publisher: "security-labs".to_string(),
            key_id: "publisher-key-1".to_string(),
        };

        assert!(matches!(
            identity.validate(),
            Err(PublisherTrustError::UnsafeIdentifier { .. })
        ));
    }

    #[test]
    fn trusted_publisher_can_be_added() {
        let mut store = PublisherTrustStore::new();

        store
            .add(trusted_publisher())
            .expect("publisher should be added");

        assert_eq!(store.publishers.len(), 1);
    }

    #[test]
    fn duplicate_publisher_is_rejected() {
        let mut store = PublisherTrustStore::new();

        store
            .add(trusted_publisher())
            .expect("first publisher should be added");

        let error = store
            .add(trusted_publisher())
            .expect_err("duplicate publisher must fail");

        assert!(matches!(
            error,
            PublisherTrustError::DuplicatePublisher { .. }
        ));
    }

    #[test]
    fn trusted_key_is_resolved() {
        let mut store = PublisherTrustStore::new();

        store
            .add(trusted_publisher())
            .expect("publisher should be added");

        let identity = PublisherIdentity {
            namespace: "okamoto".to_string(),
            publisher: "security-labs".to_string(),
            key_id: "publisher-key-1".to_string(),
        };

        let key = store
            .trusted_key(&identity)
            .expect("trusted key should resolve");

        assert_eq!(key, "PUBLIC_KEY_PLACEHOLDER");
    }

    #[test]
    fn unknown_key_is_not_trusted() {
        let mut store = PublisherTrustStore::new();

        store
            .add(trusted_publisher())
            .expect("publisher should be added");

        let identity = PublisherIdentity {
            namespace: "okamoto".to_string(),
            publisher: "security-labs".to_string(),
            key_id: "unknown-key".to_string(),
        };

        let error = store
            .trusted_key(&identity)
            .expect_err("unknown key must fail");

        assert!(matches!(error, PublisherTrustError::KeyNotTrusted { .. }));
    }

    #[test]
    fn unknown_publisher_is_not_trusted() {
        let store = PublisherTrustStore::new();

        let identity = PublisherIdentity {
            namespace: "unknown".to_string(),
            publisher: "publisher".to_string(),
            key_id: "publisher-key-1".to_string(),
        };

        let error = store
            .trusted_key(&identity)
            .expect_err("unknown publisher must fail");

        assert!(matches!(
            error,
            PublisherTrustError::PublisherNotTrusted { .. }
        ));
    }
}
