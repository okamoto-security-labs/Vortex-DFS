//! Runtime operation definitions.
//!
//! Every protected action processed by Vortex should be represented by
//! an explicit operation instead of relying on arbitrary strings.

use serde::{Deserialize, Serialize};

/// Operations recognized by the Vortex deterministic runtime.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub enum Operation {
    /// Runtime or service health verification.
    HealthCheck,

    /// Sensitive-data detection and anonymization.
    Anonymize,

    /// Cryptographic payload signing.
    Sign,

    /// Cryptographic signature verification.
    Verify,

    /// Cryptographic-agility or algorithm audit.
    CryptoAudit,

    /// API-key or client credential provisioning.
    ProvisionApiKey,

    /// Hardware or device identity registration.
    RegisterHardware,

    /// Validation and execution of an AI-agent tool request.
    AgentToolExecution,

    /// Distribution of a compact policy decision to the kernel.
    KernelPolicyUpdate,

    /// Operation not recognized by the current runtime version.
    #[default]
    Unknown,
}

impl Operation {
    /// Returns a stable machine-readable operation name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HealthCheck => "health_check",
            Self::Anonymize => "anonymize",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::CryptoAudit => "crypto_audit",
            Self::ProvisionApiKey => "provision_api_key",
            Self::RegisterHardware => "register_hardware",
            Self::AgentToolExecution => "agent_tool_execution",
            Self::KernelPolicyUpdate => "kernel_policy_update",
            Self::Unknown => "unknown",
        }
    }

    /// Indicates whether the operation changes protected state.
    pub const fn mutates_state(self) -> bool {
        matches!(
            self,
            Self::Sign
                | Self::ProvisionApiKey
                | Self::RegisterHardware
                | Self::AgentToolExecution
                | Self::KernelPolicyUpdate
        )
    }

    /// Indicates whether the operation should normally generate a
    /// security audit event.
    pub const fn requires_audit(self) -> bool {
        !matches!(self, Self::HealthCheck | Self::Unknown)
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_has_stable_machine_name() {
        assert_eq!(Operation::Anonymize.as_str(), "anonymize");
        assert_eq!(
            Operation::AgentToolExecution.as_str(),
            "agent_tool_execution"
        );
    }

    #[test]
    fn health_check_does_not_require_audit() {
        assert!(!Operation::HealthCheck.requires_audit());
    }

    #[test]
    fn security_operations_require_audit() {
        assert!(Operation::Anonymize.requires_audit());
        assert!(Operation::Verify.requires_audit());
        assert!(Operation::KernelPolicyUpdate.requires_audit());
    }

    #[test]
    fn mutating_operations_are_explicit() {
        assert!(Operation::ProvisionApiKey.mutates_state());
        assert!(Operation::RegisterHardware.mutates_state());
        assert!(!Operation::Verify.mutates_state());
        assert!(!Operation::CryptoAudit.mutates_state());
    }

    #[test]
    fn unknown_is_the_default_operation() {
        assert_eq!(Operation::default(), Operation::Unknown);
    }

    #[test]
    fn display_uses_stable_machine_name() {
        assert_eq!(Operation::CryptoAudit.to_string(), "crypto_audit");
    }
}
