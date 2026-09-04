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

COMMANDS:
    policy validate    Validate a Vortex RuntimePolicy bundle
    policy inspect     Inspect bundle metadata and policy requirements
    policy seal        Compute and persist SHA-256 integrity metadata"
    );

    process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("VORTEX ERROR");
    eprintln!();
    eprintln!("error: {}", message.as_ref());

    process::exit(1);
}

fn read_bundle(path: &str) -> VortexPolicyBundle {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format!("cannot read '{path}': {error}")));

    serde_json::from_str(&contents)
        .unwrap_or_else(|error| fail(format!("cannot parse '{path}': {error}")))
}

fn validate_policy(path: &str) {
    let bundle = read_bundle(path);

    bundle
        .validate()
        .unwrap_or_else(|error| fail(format!("{error:?}")));

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
    println!("file:                    {}", Path::new(path).display());
    println!("name:                    {}", bundle.metadata.name);
    println!("version:                 {}", bundle.metadata.version);
    println!("policy_id:               {}", bundle.policy.id);
    println!("api_version:             {}", bundle.api_version);
    println!("kind:                    {}", bundle.kind);
    println!(
        "author:                  {}",
        bundle.metadata.author.as_deref().unwrap_or("unknown")
    );
    println!(
        "description:             {}",
        bundle.metadata.description.as_deref().unwrap_or("none")
    );
    println!("allowed_operations:      {operations}");
    println!("required_scopes:         {scopes}");
    println!(
        "require_identity:        {}",
        bundle.policy.require_identity
    );
    println!(
        "require_payload_integrity: {}",
        bundle.policy.require_payload_integrity
    );
    println!(
        "require_signature:       {}",
        bundle.policy.require_signature
    );
    println!(
        "require_anonymization:   {}",
        bundle.policy.require_anonymization
    );
    println!("minimum_trust_band:      {minimum_trust}");
    println!(
        "require_replay_protection: {}",
        bundle.policy.require_replay_protection
    );
    println!("audit_required:          {}", bundle.policy.audit_required);
    println!("fail_closed:             {}", bundle.policy.fail_closed);
    println!("integrity:               {integrity}");
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

        _ => usage(),
    }
}
