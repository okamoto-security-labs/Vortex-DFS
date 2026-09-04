//! Vortex command-line interface.
//!
//! Policy tooling for portable RuntimePolicy bundles.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use vortex_dfs::{
    policy_store::PolicyStore, registry::PolicyRegistryIndex, runtime::VortexPolicyBundle,
};

fn usage() -> ! {
    eprintln!(
        "Vortex CLI

USAGE:
    vortex policy validate <FILE|POLICY@VERSION>
    vortex policy inspect  <FILE|POLICY@VERSION>
    vortex policy seal     <FILE>
    vortex policy install  <FILE|POLICY@VERSION>
    vortex policy pull     <URL|REGISTRY_REF>
    vortex policy list
    vortex registry list

COMMANDS:
    policy validate    Validate a Vortex RuntimePolicy bundle
    policy inspect     Inspect bundle metadata and policy requirements
    policy seal        Compute and persist SHA-256 integrity metadata
    policy install     Install a validated bundle into the local Vortex cache
    policy pull        Fetch, validate, and install a remote policy bundle or registry reference
    policy list        List locally installed policy bundles
    registry list      List policies published by the configured registry"
    );

    process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("VORTEX ERROR");
    eprintln!();
    eprintln!("error: {}", message.as_ref());
    process::exit(1);
}

fn store() -> PolicyStore {
    PolicyStore::from_env().unwrap_or_else(|error| fail(error.to_string()))
}

fn read_bundle(reference: &str) -> VortexPolicyBundle {
    store()
        .load(reference)
        .unwrap_or_else(|error| fail(error.to_string()))
}

fn validate_bundle(bundle: &VortexPolicyBundle) {
    bundle
        .validate()
        .unwrap_or_else(|error| fail(format!("{error:?}")));
}

fn validate_policy(reference: &str) {
    let bundle = read_bundle(reference);
    validate_bundle(&bundle);

    let integrity = match &bundle.integrity {
        Some(value) => format!("{}:{}", value.algorithm, value.digest),
        None => "unsigned".to_string(),
    };

    println!("VALID VORTEX POLICY BUNDLE");
    println!();
    println!("file:       {}", Path::new(reference).display());
    println!("name:       {}", bundle.metadata.name);
    println!("version:    {}", bundle.metadata.version);
    println!("policy:     {}", bundle.policy.id);
    println!("api:        {}", bundle.api_version);
    println!("integrity:  {integrity}");
    println!("status:     VALID");
}

fn inspect_policy(reference: &str) {
    let bundle = read_bundle(reference);

    let integrity = match &bundle.integrity {
        Some(value) => format!("{}:{}", value.algorithm, value.digest),
        None => "unsigned".to_string(),
    };

    let operations = bundle
        .policy
        .allowed_operations
        .iter()
        .map(|operation| format!("{operation:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    let scopes = if bundle.policy.required_scopes.is_empty() {
        "none".to_string()
    } else {
        bundle
            .policy
            .required_scopes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };

    let minimum_trust = bundle
        .policy
        .minimum_trust_band
        .map(|band| band.to_string())
        .unwrap_or_else(|| "none".to_string());

    println!("VORTEX POLICY BUNDLE");
    println!();
    println!("file:                      {reference}");
    println!("name:                      {}", bundle.metadata.name);
    println!("version:                   {}", bundle.metadata.version);
    println!("policy_id:                 {}", bundle.policy.id);
    println!("api_version:               {}", bundle.api_version);
    println!("kind:                      {}", bundle.kind);
    println!(
        "author:                    {}",
        bundle.metadata.author.as_deref().unwrap_or("unknown")
    );
    println!(
        "description:               {}",
        bundle.metadata.description.as_deref().unwrap_or("none")
    );
    println!("allowed_operations:        {operations}");
    println!("required_scopes:           {scopes}");
    println!(
        "require_identity:          {}",
        bundle.policy.require_identity
    );
    println!(
        "require_payload_integrity: {}",
        bundle.policy.require_payload_integrity
    );
    println!(
        "require_signature:         {}",
        bundle.policy.require_signature
    );
    println!(
        "require_anonymization:     {}",
        bundle.policy.require_anonymization
    );
    println!("minimum_trust_band:        {minimum_trust}");
    println!(
        "require_replay_protection: {}",
        bundle.policy.require_replay_protection
    );
    println!(
        "audit_required:            {}",
        bundle.policy.audit_required
    );
    println!("fail_closed:               {}", bundle.policy.fail_closed);
    println!("integrity:                 {integrity}");
}

fn seal_policy(path: &str) {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format!("cannot read '{path}': {error}")));

    let bundle: VortexPolicyBundle = serde_json::from_str(&contents)
        .unwrap_or_else(|error| fail(format!("cannot parse '{path}': {error}")));

    let bundle = bundle
        .seal()
        .unwrap_or_else(|error| fail(format!("{error:?}")));

    let serialized = serde_json::to_string_pretty(&bundle)
        .unwrap_or_else(|error| fail(format!("cannot serialize sealed bundle: {error}")));

    let target = PathBuf::from(path);

    fs::write(&target, format!("{serialized}\n"))
        .unwrap_or_else(|error| fail(format!("cannot write '{}': {error}", target.display())));

    let integrity = bundle
        .integrity
        .as_ref()
        .expect("sealed bundle must contain integrity metadata");

    println!("SEALED VORTEX POLICY BUNDLE");
    println!();
    println!("file:       {}", target.display());
    println!("algorithm:  {}", integrity.algorithm);
    println!("digest:     {}", integrity.digest);
    println!("status:     SEALED");
}

fn install_policy(reference: &str) {
    let policy_store = store();

    let bundle = policy_store
        .load(reference)
        .unwrap_or_else(|error| fail(error.to_string()));

    let target = policy_store
        .install(&bundle)
        .unwrap_or_else(|error| fail(error.to_string()));

    println!("INSTALLED VORTEX POLICY BUNDLE");
    println!();
    println!("policy:    {}", bundle.policy.id);
    println!("version:   {}", bundle.policy.version);
    println!("source:    {reference}");
    println!("installed: {}", target.display());
    println!("status:    INSTALLED");
}

const MAX_REMOTE_POLICY_BYTES: usize = 1024 * 1024;
const REMOTE_POLICY_TIMEOUT_SECS: u64 = 10;

fn registry_base() -> String {
    env::var("VORTEX_REGISTRY_BASE")
        .unwrap_or_else(|_| "https://registry.vortexdfs.com".to_string())
}

fn resolve_pull_source(source: &str) -> Result<String, String> {
    if source.starts_with("https://") || source.starts_with("http://") {
        return Ok(source.to_string());
    }

    let (path, version) = source.rsplit_once('@').ok_or_else(|| {
        format!("invalid registry reference '{source}': expected namespace/name@version")
    })?;

    let (namespace, name) = path.split_once('/').ok_or_else(|| {
        format!("invalid registry reference '{source}': expected namespace/name@version")
    })?;

    for (field, value) in [
        ("namespace", namespace),
        ("policy name", name),
        ("version", version),
    ] {
        let safe = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

        if !safe {
            return Err(format!(
                "invalid {field} '{value}' in registry reference '{source}'"
            ));
        }
    }

    let base = registry_base().trim_end_matches('/').to_string();

    Ok(format!("{base}/{namespace}/{name}/{version}/policy.json"))
}

fn validate_remote_source(url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| format!("invalid policy source '{url}': {error}"))?;

    match parsed.scheme() {
        "https" => Ok(parsed),

        "http" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| format!("policy source '{url}' has no host"))?;

            if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                Ok(parsed)
            } else {
                Err(format!(
                    "insecure remote policy source '{url}': HTTP is allowed only for localhost"
                ))
            }
        }

        scheme => Err(format!(
            "unsupported policy source scheme '{scheme}': expected https://"
        )),
    }
}

async fn fetch_remote_bytes(
    url: &str,
    resource_name: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    use std::time::Duration;

    let parsed = validate_remote_source(url)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REMOTE_POLICY_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("cannot initialize HTTP client: {error}"))?;

    let response = client
        .get(parsed)
        .send()
        .await
        .map_err(|error| format!("cannot fetch '{url}': {error}"))?;

    let status = response.status();

    if !status.is_success() {
        return Err(format!(
            "remote source returned HTTP {} for '{}'",
            status, url
        ));
    }

    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes as u64 {
            return Err(format!("{resource_name} exceeds {max_bytes} byte limit"));
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|error| format!("cannot read {resource_name} from '{url}': {error}"))?;

    if body.len() > max_bytes {
        return Err(format!("{resource_name} exceeds {max_bytes} byte limit"));
    }

    Ok(body.to_vec())
}

async fn fetch_remote_bundle(url: &str) -> Result<VortexPolicyBundle, String> {
    let body = fetch_remote_bytes(url, "remote policy bundle", MAX_REMOTE_POLICY_BYTES).await?;

    let bundle: VortexPolicyBundle = serde_json::from_slice(&body)
        .map_err(|error| format!("cannot parse remote policy bundle from '{url}': {error}"))?;

    bundle.validate().map_err(|error| format!("{error:?}"))?;

    Ok(bundle)
}

async fn fetch_registry_index() -> Result<(String, PolicyRegistryIndex), String> {
    let base = registry_base().trim_end_matches('/').to_string();
    let url = format!("{base}/index.json");

    let body = fetch_remote_bytes(&url, "registry index", MAX_REMOTE_POLICY_BYTES).await?;

    let index: PolicyRegistryIndex = serde_json::from_slice(&body)
        .map_err(|error| format!("cannot parse registry index from '{url}': {error}"))?;

    index.validate().map_err(|error| format!("{error:?}"))?;

    Ok((url, index))
}

async fn list_registry() {
    let (url, index) = fetch_registry_index()
        .await
        .unwrap_or_else(|error| fail(error));

    println!("VORTEX POLICY REGISTRY");
    println!();
    println!("source:   {url}");
    println!("policies: {}", index.policies.len());
    println!();

    if index.policies.is_empty() {
        println!("No policies published.");
        return;
    }

    for policy in index.policies {
        println!("{}", policy.latest_reference());

        if let Some(description) = policy.description {
            println!("  {description}");
        }

        println!("  versions: {}", policy.versions.join(", "));

        println!();
    }
}

async fn pull_policy(source: &str) {
    let url = resolve_pull_source(source).unwrap_or_else(|error| fail(error));

    let bundle = fetch_remote_bundle(&url)
        .await
        .unwrap_or_else(|error| fail(error));

    let policy_store = store();

    let target = policy_store
        .install(&bundle)
        .unwrap_or_else(|error| fail(error.to_string()));

    println!("PULLED VORTEX POLICY BUNDLE");
    println!();
    println!("policy:    {}", bundle.policy.id);
    println!("version:   {}", bundle.policy.version);
    println!("source:    {source}");
    println!("resolved:  {url}");
    println!("installed: {}", target.display());
    println!("status:    INSTALLED");
}

fn list_policies() {
    let entries = store()
        .list()
        .unwrap_or_else(|error| fail(error.to_string()));

    if entries.is_empty() {
        println!("No Vortex policies installed.");
        return;
    }

    println!("INSTALLED VORTEX POLICIES");
    println!();

    for entry in entries {
        println!("{}@{}", entry.policy_id, entry.version);
        println!("  name: {}", entry.name);
        println!("  path: {}", entry.path.display());
        println!();
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    match args.as_slice() {
        [_, command, action, reference] if command == "policy" && action == "validate" => {
            validate_policy(reference);
        }

        [_, command, action, reference] if command == "policy" && action == "inspect" => {
            inspect_policy(reference);
        }

        [_, command, action, path] if command == "policy" && action == "seal" => {
            seal_policy(path);
        }

        [_, command, action, reference] if command == "policy" && action == "install" => {
            install_policy(reference);
        }

        [_, command, action, url] if command == "policy" && action == "pull" => {
            pull_policy(url).await;
        }

        [_, command, action] if command == "policy" && action == "list" => {
            list_policies();
        }

        [_, command, action] if command == "registry" && action == "list" => {
            list_registry().await;
        }

        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_remote_source_is_allowed() {
        assert!(validate_remote_source("https://registry.example.com/policy.json").is_ok());
    }

    #[test]
    fn localhost_http_source_is_allowed() {
        assert!(validate_remote_source("http://127.0.0.1:8000/policy.json").is_ok());

        assert!(validate_remote_source("http://localhost:8000/policy.json").is_ok());
    }

    #[test]
    fn external_http_source_is_rejected() {
        let error = validate_remote_source("http://registry.example.com/policy.json")
            .expect_err("external plaintext HTTP must fail");

        assert!(error.contains("HTTP is allowed only for localhost"));
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        let error =
            validate_remote_source("file:///tmp/policy.json").expect_err("file scheme must fail");

        assert!(error.contains("unsupported policy source scheme"));
    }
}

#[cfg(test)]
mod registry_reference_tests {
    use super::*;

    #[test]
    fn direct_https_url_is_preserved() {
        let source = "https://example.com/policy.json";

        assert_eq!(
            resolve_pull_source(source).expect("direct URL should resolve"),
            source
        );
    }

    #[test]
    fn registry_reference_resolves_to_policy_path() {
        unsafe {
            env::set_var("VORTEX_REGISTRY_BASE", "https://registry.example.com");
        }

        let resolved = resolve_pull_source("okamoto/agent-tool-execution@0.1.0")
            .expect("registry reference should resolve");

        assert_eq!(
            resolved,
            "https://registry.example.com/okamoto/agent-tool-execution/0.1.0/policy.json"
        );

        unsafe {
            env::remove_var("VORTEX_REGISTRY_BASE");
        }
    }

    #[test]
    fn malformed_registry_reference_is_rejected() {
        let error = resolve_pull_source("agent-tool-execution")
            .expect_err("missing namespace and version must fail");

        assert!(error.contains("expected namespace/name@version"));
    }

    #[test]
    fn traversal_in_registry_reference_is_rejected() {
        let error =
            resolve_pull_source("../../escape@0.1.0").expect_err("unsafe namespace must fail");

        assert!(error.contains("invalid namespace") || error.contains("invalid policy name"));
    }
}
