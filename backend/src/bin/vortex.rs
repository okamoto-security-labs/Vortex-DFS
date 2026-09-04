//! Vortex command-line interface.
//!
//! Policy tooling for portable RuntimePolicy bundles.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use vortex_dfs::runtime::VortexPolicyBundle;

fn usage() -> ! {
    eprintln!(
        "Vortex CLI

USAGE:
    vortex policy validate <FILE>
    vortex policy inspect  <FILE>
    vortex policy seal     <FILE>
    vortex policy install  <FILE>
    vortex policy list

COMMANDS:
    policy validate    Validate a Vortex RuntimePolicy bundle
    policy inspect     Inspect bundle metadata and policy requirements
    policy seal        Compute and persist SHA-256 integrity metadata
    policy install     Install a validated bundle into the local Vortex cache
    policy list        List locally installed policy bundles"
    );

    process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("VORTEX ERROR");
    eprintln!();
    eprintln!("error: {}", message.as_ref());

    process::exit(1);
}

fn resolve_policy_reference(reference: &str) -> PathBuf {
    let direct = PathBuf::from(reference);

    if direct.exists() {
        return direct;
    }

    if let Some((policy_id, version)) = reference.rsplit_once('@') {
        if policy_id.is_empty() || version.is_empty() {
            fail(format!("invalid policy reference '{reference}'"));
        }

        let installed = policy_store_root()
            .join(policy_id)
            .join(version)
            .join("policy.json");

        if installed.exists() {
            return installed;
        }

        fail(format!("policy '{reference}' is not installed"));
    }

    fail(format!("cannot resolve policy reference '{reference}'"));
}

fn read_bundle(reference: &str) -> VortexPolicyBundle {
    let path = resolve_policy_reference(reference);

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| fail(format!("cannot read '{}': {error}", path.display())));

    serde_json::from_str(&contents)
        .unwrap_or_else(|error| fail(format!("cannot parse '{}': {error}", path.display())))
}

fn vortex_home() -> PathBuf {
    if let Ok(path) = env::var("VORTEX_HOME") {
        return PathBuf::from(path);
    }

    let home = env::var("HOME")
        .unwrap_or_else(|_| fail("HOME is not set and VORTEX_HOME was not provided"));

    PathBuf::from(home).join(".vortex")
}

fn policy_store_root() -> PathBuf {
    vortex_home().join("policies")
}

fn validate_bundle(bundle: &VortexPolicyBundle) {
    bundle
        .validate()
        .unwrap_or_else(|error| fail(format!("{error:?}")));
}

fn validate_policy(path: &str) {
    let bundle = read_bundle(path);

    validate_bundle(&bundle);

    let integrity = match &bundle.integrity {
        Some(value) => format!("{}:{}", value.algorithm, value.digest),
        None => "unsigned".to_string(),
    };

    println!("VALID VORTEX POLICY BUNDLE");
    println!();
    println!("file:       {}", Path::new(path).display());
    println!("name:       {}", bundle.metadata.name);
    println!("version:    {}", bundle.metadata.version);
    println!("policy:     {}", bundle.policy.id);
    println!("api:        {}", bundle.api_version);
    println!("integrity:  {integrity}");
    println!("status:     VALID");
}

fn inspect_policy(path: &str) {
    let bundle = read_bundle(path);

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
    println!("file:                      {}", Path::new(path).display());
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
    let bundle = read_bundle(path)
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

fn install_policy(path: &str) {
    let bundle = read_bundle(path);

    validate_bundle(&bundle);

    let target_dir = policy_store_root()
        .join(&bundle.policy.id)
        .join(&bundle.policy.version);

    fs::create_dir_all(&target_dir).unwrap_or_else(|error| {
        fail(format!(
            "cannot create policy directory '{}': {error}",
            target_dir.display()
        ))
    });

    let target = target_dir.join("policy.json");

    let serialized = serde_json::to_string_pretty(&bundle)
        .unwrap_or_else(|error| fail(format!("cannot serialize bundle: {error}")));

    fs::write(&target, format!("{serialized}\n")).unwrap_or_else(|error| {
        fail(format!(
            "cannot install policy to '{}': {error}",
            target.display()
        ))
    });

    println!("INSTALLED VORTEX POLICY BUNDLE");
    println!();
    println!("policy:    {}", bundle.policy.id);
    println!("version:   {}", bundle.policy.version);
    println!("source:    {}", Path::new(path).display());
    println!("installed: {}", target.display());
    println!("status:    INSTALLED");
}

fn list_policies() {
    let root = policy_store_root();

    if !root.exists() {
        println!("No Vortex policies installed.");
        return;
    }

    let mut entries = Vec::new();

    let policy_dirs = fs::read_dir(&root)
        .unwrap_or_else(|error| fail(format!("cannot read '{}': {error}", root.display())));

    for policy_dir in policy_dirs {
        let policy_dir =
            policy_dir.unwrap_or_else(|error| fail(format!("cannot read policy entry: {error}")));

        let policy_path = policy_dir.path();

        if !policy_path.is_dir() {
            continue;
        }

        let versions = fs::read_dir(&policy_path).unwrap_or_else(|error| {
            fail(format!(
                "cannot read policy directory '{}': {error}",
                policy_path.display()
            ))
        });

        for version in versions {
            let version =
                version.unwrap_or_else(|error| fail(format!("cannot read version entry: {error}")));

            let version_path = version.path();

            if !version_path.is_dir() {
                continue;
            }

            let bundle_path = version_path.join("policy.json");

            if !bundle_path.exists() {
                continue;
            }

            let contents = fs::read_to_string(&bundle_path).unwrap_or_else(|error| {
                fail(format!(
                    "cannot read installed bundle '{}': {error}",
                    bundle_path.display()
                ))
            });

            let bundle: VortexPolicyBundle =
                serde_json::from_str(&contents).unwrap_or_else(|error| {
                    fail(format!(
                        "cannot parse installed bundle '{}': {error}",
                        bundle_path.display()
                    ))
                });

            entries.push((
                bundle.policy.id,
                bundle.policy.version,
                bundle.metadata.name,
                bundle_path,
            ));
        }
    }

    entries.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));

    if entries.is_empty() {
        println!("No Vortex policies installed.");
        return;
    }

    println!("INSTALLED VORTEX POLICIES");
    println!();

    for (policy_id, version, name, path) in entries {
        println!("{policy_id}@{version}");
        println!("  name: {name}");
        println!("  path: {}", path.display());
        println!();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.as_slice() {
        [_, command, action, path] if command == "policy" && action == "validate" => {
            validate_policy(path);
        }

        [_, command, action, path] if command == "policy" && action == "inspect" => {
            inspect_policy(path);
        }

        [_, command, action, path] if command == "policy" && action == "seal" => {
            seal_policy(path);
        }

        [_, command, action, path] if command == "policy" && action == "install" => {
            install_policy(path);
        }

        [_, command, action] if command == "policy" && action == "list" => {
            list_policies();
        }

        _ => usage(),
    }
}
