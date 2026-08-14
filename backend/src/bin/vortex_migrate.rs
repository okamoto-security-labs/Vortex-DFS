//! Applies Vortex database migrations during deployment.
//!
//! This binary is intentionally separate from the HTTP server.

use vortex_dfs::provisioner::{get_pool, init_db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    init_db().await.map_err(std::io::Error::other)?;

    let pool = get_pool().map_err(std::io::Error::other)?.clone();

    sqlx::migrate!().run(&pool).await?;

    println!("Vortex database migrations applied successfully.");

    Ok(())
}
