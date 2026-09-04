//! Local storage and resolution for portable Vortex policy bundles.
//!
//! PolicyStore owns filesystem semantics for installed policies.
//! Registry/network concerns intentionally live outside this module.

use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

use crate::runtime::{PolicyBundleError, VortexPolicyBundle};

#[derive(Debug)]
pub enum PolicyStoreError {
    HomeUnavailable,
    InvalidReference(String),
    UnsafeIdentifier {
        field: &'static str,
        value: String,
    },
    NotInstalled(String),
    Io {
        context: String,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Serialize(serde_json::Error),
    InvalidBundle(PolicyBundleError),
}

impl fmt::Display for PolicyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeUnavailable => {
                write!(f, "HOME is not set and VORTEX_HOME was not provided")
            }
            Self::InvalidReference(reference) => {
                write!(f, "invalid policy reference '{reference}'")
            }
            Self::UnsafeIdentifier { field, value } => {
                write!(f, "unsafe {field} '{value}'")
            }
            Self::NotInstalled(reference) => {
                write!(f, "policy '{reference}' is not installed")
            }
            Self::Io { context, source } => {
                write!(f, "{context}: {source}")
            }
            Self::Parse { path, source } => {
                write!(f, "cannot parse '{}': {source}", path.display())
            }
            Self::Serialize(source) => {
                write!(f, "cannot serialize policy bundle: {source}")
            }
            Self::InvalidBundle(error) => {
                write!(f, "invalid policy bundle: {error:?}")
            }
        }
    }
}

impl std::error::Error for PolicyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPolicy {
    pub policy_id: String,
    pub version: String,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    root: PathBuf,
}

impl PolicyStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_env() -> Result<Self, PolicyStoreError> {
        let vortex_home = if let Ok(path) = env::var("VORTEX_HOME") {
            PathBuf::from(path)
        } else {
            let home = env::var("HOME").map_err(|_| PolicyStoreError::HomeUnavailable)?;
            PathBuf::from(home).join(".vortex")
        };

        Ok(Self::new(vortex_home.join("policies")))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, policy_id: &str, version: &str) -> Result<PathBuf, PolicyStoreError> {
        validate_identifier("policy id", policy_id)?;
        validate_identifier("policy version", version)?;

        Ok(self.root.join(policy_id).join(version).join("policy.json"))
    }

    pub fn resolve(&self, reference: &str) -> Result<PathBuf, PolicyStoreError> {
        let direct = PathBuf::from(reference);

        if direct.exists() {
            return Ok(direct);
        }

        let (policy_id, version) = reference
            .rsplit_once('@')
            .ok_or_else(|| PolicyStoreError::InvalidReference(reference.to_string()))?;

        if policy_id.is_empty() || version.is_empty() {
            return Err(PolicyStoreError::InvalidReference(reference.to_string()));
        }

        let installed = self.path_for(policy_id, version)?;

        if installed.exists() {
            return Ok(installed);
        }

        Err(PolicyStoreError::NotInstalled(reference.to_string()))
    }

    pub fn load(&self, reference: &str) -> Result<VortexPolicyBundle, PolicyStoreError> {
        let path = self.resolve(reference)?;
        self.load_path(&path)
    }

    pub fn load_path(&self, path: &Path) -> Result<VortexPolicyBundle, PolicyStoreError> {
        let contents = fs::read_to_string(path).map_err(|source| PolicyStoreError::Io {
            context: format!("cannot read '{}'", path.display()),
            source,
        })?;

        serde_json::from_str(&contents).map_err(|source| PolicyStoreError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn install(&self, bundle: &VortexPolicyBundle) -> Result<PathBuf, PolicyStoreError> {
        bundle.validate().map_err(PolicyStoreError::InvalidBundle)?;

        let target = self.path_for(&bundle.policy.id, &bundle.policy.version)?;

        let parent = target.parent().expect("policy path always has a parent");

        fs::create_dir_all(parent).map_err(|source| PolicyStoreError::Io {
            context: format!("cannot create policy directory '{}'", parent.display()),
            source,
        })?;

        let serialized =
            serde_json::to_string_pretty(bundle).map_err(PolicyStoreError::Serialize)?;

        fs::write(&target, format!("{serialized}\n")).map_err(|source| PolicyStoreError::Io {
            context: format!("cannot install policy to '{}'", target.display()),
            source,
        })?;

        Ok(target)
    }

    pub fn list(&self) -> Result<Vec<InstalledPolicy>, PolicyStoreError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        let policy_dirs = fs::read_dir(&self.root).map_err(|source| PolicyStoreError::Io {
            context: format!("cannot read '{}'", self.root.display()),
            source,
        })?;

        for policy_dir in policy_dirs {
            let policy_dir = policy_dir.map_err(|source| PolicyStoreError::Io {
                context: "cannot read policy entry".to_string(),
                source,
            })?;

            let policy_path = policy_dir.path();

            if !policy_path.is_dir() {
                continue;
            }

            let versions = fs::read_dir(&policy_path).map_err(|source| PolicyStoreError::Io {
                context: format!("cannot read policy directory '{}'", policy_path.display()),
                source,
            })?;

            for version in versions {
                let version = version.map_err(|source| PolicyStoreError::Io {
                    context: "cannot read policy version entry".to_string(),
                    source,
                })?;

                let version_path = version.path();

                if !version_path.is_dir() {
                    continue;
                }

                let bundle_path = version_path.join("policy.json");

                if !bundle_path.exists() {
                    continue;
                }

                let bundle = self.load_path(&bundle_path)?;

                entries.push(InstalledPolicy {
                    policy_id: bundle.policy.id,
                    version: bundle.policy.version,
                    name: bundle.metadata.name,
                    path: bundle_path,
                });
            }
        }

        entries.sort_by(|a, b| (&a.policy_id, &a.version).cmp(&(&b.policy_id, &b.version)));

        Ok(entries)
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), PolicyStoreError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

    if safe {
        Ok(())
    } else {
        Err(PolicyStoreError::UnsafeIdentifier {
            field,
            value: value.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::runtime::{Operation, RuntimePolicy};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_store() -> PolicyStore {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();

        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

        PolicyStore::new(
            env::temp_dir()
                .join(format!("vortex-policy-store-{nonce}-{counter}"))
                .join("policies"),
        )
    }

    fn test_bundle() -> VortexPolicyBundle {
        let policy = RuntimePolicy::new("runtime.agent.tool_execution", "0.1.0")
            .allow_operation(Operation::Anonymize)
            .with_identity_requirement(true)
            .with_required_scope("agent:execute")
            .with_fail_closed(true);

        VortexPolicyBundle::new(
            "agent-tool-execution",
            Some("Portable Vortex policy bundle.".to_string()),
            Some("Okamoto Security Labs".to_string()),
            policy,
        )
        .seal()
        .expect("bundle should seal")
    }

    #[test]
    fn install_and_resolve_round_trip() {
        let store = temporary_store();
        let bundle = test_bundle();

        let installed = store.install(&bundle).expect("bundle should install");

        assert!(installed.exists());

        let resolved = store
            .resolve("runtime.agent.tool_execution@0.1.0")
            .expect("installed reference should resolve");

        assert_eq!(resolved, installed);

        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn load_installed_bundle_preserves_semantics() {
        let store = temporary_store();
        let bundle = test_bundle();

        store.install(&bundle).expect("bundle should install");

        let loaded = store
            .load("runtime.agent.tool_execution@0.1.0")
            .expect("installed bundle should load");

        assert_eq!(loaded, bundle);

        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn list_returns_installed_bundle() {
        let store = temporary_store();
        let bundle = test_bundle();

        store.install(&bundle).expect("bundle should install");

        let entries = store.list().expect("store should list");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].policy_id, "runtime.agent.tool_execution");
        assert_eq!(entries[0].version, "0.1.0");
        assert_eq!(entries[0].name, "agent-tool-execution");

        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn missing_reference_is_not_installed() {
        let store = temporary_store();

        let error = store
            .resolve("runtime.agent.missing@9.9.9")
            .expect_err("missing policy must fail");

        assert!(matches!(error, PolicyStoreError::NotInstalled(_)));

        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn unsafe_policy_id_cannot_escape_store() {
        let store = temporary_store();

        let error = store
            .path_for("../../escape", "0.1.0")
            .expect_err("path traversal must fail");

        assert!(matches!(
            error,
            PolicyStoreError::UnsafeIdentifier {
                field: "policy id",
                ..
            }
        ));

        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn unsafe_version_cannot_escape_store() {
        let store = temporary_store();

        let error = store
            .path_for("runtime.safe", "../escape")
            .expect_err("path traversal must fail");

        assert!(matches!(
            error,
            PolicyStoreError::UnsafeIdentifier {
                field: "policy version",
                ..
            }
        ));

        fs::remove_dir_all(store.root()).ok();
    }
}
