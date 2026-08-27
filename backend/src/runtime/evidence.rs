//! Security evidence collected by the Vortex runtime.
//!
//! Evidence represents validated security-relevant facts discovered
//! during request processing.
//!
//! Optional fields distinguish a negative result from a signal that was
//! not evaluated.

use crate::runtime::RuntimeTrustBand;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Extensible evidence value supported by the runtime.
///
/// `BTreeMap` is used by `SecurityEvidence` to preserve deterministic
/// ordering during serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EvidenceValue {
    Boolean(bool),
    Integer(i64),
    UnsignedInteger(u64),
    Float(f64),
    Text(String),
}

/// Named security evidence collected during request processing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvidence {
    /// Whether the request passed structural validation.
    pub structural_validity: Option<bool>,

    /// Whether the requester identity was verified.
    pub identity_verified: Option<bool>,

    /// Whether payload integrity evidence was successfully validated.
    pub payload_integrity_valid: Option<bool>,

    /// Whether a cryptographic signature was evaluated as valid.
    pub signature_valid: Option<bool>,

    /// Whether sensitive information was detected in the payload.
    pub sensitive_data_detected: Option<bool>,

    /// Whether replay behavior was detected.
    pub replay_detected: Option<bool>,

    /// Optional deterministic risk value produced by a feature.
    ///
    /// This value must not automatically be interpreted as a
    /// probability.
    pub risk_score: Option<f64>,

    /// Operational trust classification assigned by the runtime.
    pub trust_band: Option<RuntimeTrustBand>,

    /// Additional named evidence fields.
    ///
    /// Arbitrary signals should be used sparingly. Security-critical
    /// evidence should become a dedicated named field whenever possible.
    #[serde(default)]
    pub signals: BTreeMap<String, EvidenceValue>,
}

impl SecurityEvidence {
    /// Creates an empty evidence collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces an extensible evidence signal.
    ///
    /// Returns the previous value when a signal with the same name
    /// already existed.
    pub fn add_signal(
        &mut self,
        name: impl Into<String>,
        value: EvidenceValue,
    ) -> Option<EvidenceValue> {
        self.signals.insert(name.into(), value)
    }

    /// Returns a named evidence signal.
    pub fn signal(&self, name: &str) -> Option<&EvidenceValue> {
        self.signals.get(name)
    }

    /// Records structural validation evidence.
    pub fn set_structural_validity(&mut self, valid: bool) {
        self.structural_validity = Some(valid);
    }

    /// Records identity verification evidence.
    pub fn set_identity_verified(&mut self, verified: bool) {
        self.identity_verified = Some(verified);
    }

    /// Records payload-integrity evidence.
    pub fn set_payload_integrity_valid(&mut self, valid: bool) {
        self.payload_integrity_valid = Some(valid);
    }

    /// Records signature-verification evidence.
    pub fn set_signature_valid(&mut self, valid: bool) {
        self.signature_valid = Some(valid);
    }

    /// Records sensitive-data detection evidence.
    pub fn set_sensitive_data_detected(&mut self, detected: bool) {
        self.sensitive_data_detected = Some(detected);
    }

    /// Records replay detection evidence.
    pub fn set_replay_detected(&mut self, detected: bool) {
        self.replay_detected = Some(detected);
    }

    /// Records a runtime risk score.
    pub fn set_risk_score(&mut self, score: f64) {
        self.risk_score = Some(score);
    }

    /// Records the evaluated operational trust band.
    pub fn set_trust_band(&mut self, trust_band: RuntimeTrustBand) {
        self.trust_band = Some(trust_band);
    }

    /// Returns whether any explicitly evaluated evidence indicates a
    /// security failure.
    pub fn contains_explicit_failure(&self) -> bool {
        self.structural_validity == Some(false)
            || self.identity_verified == Some(false)
            || self.payload_integrity_valid == Some(false)
            || self.signature_valid == Some(false)
            || self.replay_detected == Some(true)
            || self.trust_band == Some(RuntimeTrustBand::Critical)
    }
}

/// Compact evidence representation suitable for decisions and external
/// responses.
///
/// The summary deliberately excludes unrestricted extensible signals.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub structural_validity: Option<bool>,
    pub identity_verified: Option<bool>,
    pub payload_integrity_valid: Option<bool>,
    pub signature_valid: Option<bool>,
    pub sensitive_data_detected: Option<bool>,
    pub replay_detected: Option<bool>,
    pub risk_score: Option<f64>,
    pub trust_band: Option<RuntimeTrustBand>,
}

impl From<&SecurityEvidence> for EvidenceSummary {
    fn from(evidence: &SecurityEvidence) -> Self {
        Self {
            structural_validity: evidence.structural_validity,
            identity_verified: evidence.identity_verified,
            payload_integrity_valid: evidence.payload_integrity_valid,
            signature_valid: evidence.signature_valid,
            sensitive_data_detected: evidence.sensitive_data_detected,
            replay_detected: evidence.replay_detected,
            risk_score: evidence.risk_score,
            trust_band: evidence.trust_band,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_starts_unevaluated() {
        let evidence = SecurityEvidence::new();

        assert_eq!(evidence.structural_validity, None);
        assert_eq!(evidence.signature_valid, None);
        assert_eq!(evidence.trust_band, None);
        assert!(!evidence.contains_explicit_failure());
    }

    #[test]
    fn signals_are_serialized_in_deterministic_order() {
        let mut evidence = SecurityEvidence::new();

        evidence.add_signal("z_signal", EvidenceValue::Boolean(true));
        evidence.add_signal("a_signal", EvidenceValue::UnsignedInteger(10));

        let names: Vec<&str> = evidence.signals.keys().map(String::as_str).collect();

        assert_eq!(names, vec!["a_signal", "z_signal"]);
    }

    #[test]
    fn adding_duplicate_signal_returns_previous_value() {
        let mut evidence = SecurityEvidence::new();

        evidence.add_signal("latency_us", EvidenceValue::UnsignedInteger(100));

        let previous = evidence.add_signal("latency_us", EvidenceValue::UnsignedInteger(200));

        assert_eq!(previous, Some(EvidenceValue::UnsignedInteger(100)));
    }

    #[test]
    fn explicit_negative_evidence_is_detected() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_signature_valid(false);

        assert!(evidence.contains_explicit_failure());
    }

    #[test]
    fn replay_detection_is_an_explicit_failure() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_replay_detected(true);

        assert!(evidence.contains_explicit_failure());
    }

    #[test]
    fn critical_trust_is_an_explicit_failure() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_trust_band(RuntimeTrustBand::Critical);

        assert!(evidence.contains_explicit_failure());
    }

    #[test]
    fn summary_copies_only_bounded_evidence() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_structural_validity(true);
        evidence.set_sensitive_data_detected(true);
        evidence.set_risk_score(0.75);
        evidence.add_signal(
            "raw_internal_detail",
            EvidenceValue::Text("not exposed".to_string()),
        );

        let summary = EvidenceSummary::from(&evidence);

        assert_eq!(summary.structural_validity, Some(true));
        assert_eq!(summary.sensitive_data_detected, Some(true));
        assert_eq!(summary.risk_score, Some(0.75));
    }
}
