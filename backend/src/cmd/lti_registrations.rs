use crate::{config::Config, db, prelude::*};


#[derive(Debug, clap::Parser)]
pub(crate) enum Args {
    /// Lists all dynamically registered LTI platforms (statically configured
    /// ones live in `[[auth.lti.platforms]]` and are not listed here).
    List,

    /// Removes the dynamic registration of the platform with the given
    /// issuer. The platform can no longer launch users into Tobira afterwards
    /// (unless it is also configured statically).
    Remove {
        /// The platform's issuer, as shown by `list`.
        issuer: String,
    },
}

pub(crate) async fn run(config: Config, args: &Args) -> Result<()> {
    let pool = db::create_pool(&config.db).await
        .context("failed to create database connection pool (database not running?)")?;
    let db = pool.get().await?;

    match args {
        Args::List => list(&db).await,
        Args::Remove { issuer } => remove(&db, issuer).await,
    }
}

async fn list(db: &db::DbConnection) -> Result<()> {
    let rows = db.query(
        "select issuer, client_id, platform_name, deployment_ids, created \
            from lti_registrations \
            order by issuer",
        &[],
    ).await?;

    if rows.is_empty() {
        println!("No dynamically registered LTI platforms.");
        return Ok(());
    }

    for row in rows {
        let issuer: String = row.get(0);
        let client_id: String = row.get(1);
        let platform_name: Option<String> = row.get(2);
        let deployment_ids: Vec<String> = row.get(3);
        let created: chrono::DateTime<chrono::Utc> = row.get(4);

        println!("- {issuer}");
        if let Some(name) = platform_name {
            println!("    platform: {name}");
        }
        println!("    client_id: {client_id}");
        println!("    deployments: [{}]", deployment_ids.join(", "));
        println!("    registered: {}", created.format("%Y-%m-%d %H:%M UTC"));
    }
    Ok(())
}

async fn remove(db: &db::DbConnection, issuer: &str) -> Result<()> {
    let affected = db.execute(
        "delete from lti_registrations where issuer = $1",
        &[&issuer],
    ).await?;

    if affected == 0 {
        bail!("no dynamic registration with issuer '{issuer}' (see `list`)");
    }
    println!("Removed the registration of '{issuer}'.");
    Ok(())
}
