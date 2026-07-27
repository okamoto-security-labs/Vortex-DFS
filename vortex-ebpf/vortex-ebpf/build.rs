use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    if std::env::var_os("AYA_BUILD_SKIP").is_some() {
        println!("cargo:warning=AYA_BUILD_SKIP set; skipping eBPF build");
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "vortex-ebpf-ebpf")
        .ok_or_else(|| anyhow!("vortex-ebpf-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };

    if let Err(err) = aya_build::build_ebpf([ebpf_package], Toolchain::default()) {
        println!("cargo:warning=skipping eBPF build because the environment is missing the required nightly/toolchain: {err}");
        Ok(())
    } else {
        Ok(())
    }
}
