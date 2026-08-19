use crate::{
    auth::config::{LtiConfig, LtiPlatform, LtiUsernameSource},
    auth::lti::registration::{self, DeploymentPolicy},
    prelude::*,
};
use super::util::TestDb;


async fn insert_registration(db: &TestDb, issuer: &str, client_id: &str) -> Result<()> {
    db.execute(
        "insert into lti_registrations (issuer, client_id, auth_login_url, keyset_url) \
            values ($1, $2, 'https://lms.example.org/auth', 'https://lms.example.org/jwks')",
        &[&issuer, &client_id],
    ).await?;
    Ok(())
}

fn config_with(platforms: Vec<LtiPlatform>) -> LtiConfig {
    LtiConfig { enabled: true, platforms, tool_key: None }
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_platform_prefers_config_and_falls_back_to_db() -> Result<()> {
    let db = TestDb::with_migrations().await?;
    insert_registration(&db, "https://moodle.example.org", "from-db").await?;

    // A config entry for the same issuer wins over the registration.
    let config = config_with(vec![LtiPlatform {
        issuer: "https://moodle.example.org".into(),
        client_id: "from-config".into(),
        deployment_id: "1".into(),
        auth_login_url: "https://lms.example.org/auth".parse().unwrap(),
        keyset_url: "https://lms.example.org/jwks".parse().unwrap(),
        username_source: LtiUsernameSource::default(),
    }]);
    let resolved = registration::resolve_platform(
        &db, &config, "https://moodle.example.org", None,
    ).await?.expect("config platform must resolve");
    assert_eq!(resolved.client_id, "from-config");
    assert!(matches!(resolved.deployments, DeploymentPolicy::Fixed(ref d) if d == "1"));

    // Without the config entry, the dynamic registration is found — with the
    // trust-on-first-use deployment policy and `custom` username source.
    let resolved = registration::resolve_platform(
        &db, &config_with(vec![]), "https://moodle.example.org", Some("from-db"),
    ).await?.expect("db registration must resolve");
    assert_eq!(resolved.client_id, "from-db");
    assert_eq!(resolved.username_source, LtiUsernameSource::Custom);
    assert!(matches!(
        resolved.deployments,
        DeploymentPolicy::TrustOnFirstUse { ref known, .. } if known.is_empty(),
    ));

    // Wrong client_id or unknown issuer must not resolve.
    let wrong_client = registration::resolve_platform(
        &db, &config_with(vec![]), "https://moodle.example.org", Some("someone-else"),
    ).await?;
    assert!(wrong_client.is_none());
    let unknown = registration::resolve_platform(
        &db, &config_with(vec![]), "https://other.example.org", None,
    ).await?;
    assert!(unknown.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn remember_deployment_appends_to_known_ids() -> Result<()> {
    let db = TestDb::with_migrations().await?;
    insert_registration(&db, "https://moodle.example.org", "client-a").await?;

    let empty_config = config_with(vec![]);
    let resolve = || registration::resolve_platform(
        &db, &empty_config, "https://moodle.example.org", None,
    );
    let DeploymentPolicy::TrustOnFirstUse { registration_id, known }
        = resolve().await?.unwrap().deployments
    else {
        panic!("expected trust-on-first-use policy");
    };
    assert!(known.is_empty());

    registration::remember_deployment(&db, registration_id, "3").await?;
    let DeploymentPolicy::TrustOnFirstUse { known, .. }
        = resolve().await?.unwrap().deployments
    else {
        panic!("expected trust-on-first-use policy");
    };
    assert_eq!(known, vec!["3"]);

    Ok(())
}
