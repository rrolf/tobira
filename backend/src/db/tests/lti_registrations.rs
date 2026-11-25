use crate::{
    auth::config::LtiUsernameSource,
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

#[tokio::test(flavor = "multi_thread")]
async fn find_registration_resolves_and_filters() -> Result<()> {
    let db = TestDb::with_migrations().await?;
    insert_registration(&db, "https://moodle.example.org", "from-db").await?;

    // The dynamic registration is found — with the trust-on-first-use
    // deployment policy and `custom` username source. (The config-beats-DB
    // precedence lives in `resolve_platform`, which needs a full HTTP context;
    // its config half is covered by unit tests in the registration module.)
    let resolved = registration::find_registration(
        &db, "https://moodle.example.org", Some("from-db"),
    ).await?.expect("db registration must resolve");
    assert_eq!(resolved.client_id, "from-db");
    assert_eq!(resolved.username_source, LtiUsernameSource::Custom);
    assert!(matches!(
        resolved.deployments,
        DeploymentPolicy::TrustOnFirstUse { ref known, .. } if known.is_empty(),
    ));

    // Wrong client_id or unknown issuer must not resolve.
    let wrong_client = registration::find_registration(
        &db, "https://moodle.example.org", Some("someone-else"),
    ).await?;
    assert!(wrong_client.is_none());
    let unknown = registration::find_registration(
        &db, "https://other.example.org", None,
    ).await?;
    assert!(unknown.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn remember_deployment_appends_to_known_ids() -> Result<()> {
    let db = TestDb::with_migrations().await?;
    insert_registration(&db, "https://moodle.example.org", "client-a").await?;

    let resolve = || registration::find_registration(
        &db, "https://moodle.example.org", None,
    );
    let DeploymentPolicy::TrustOnFirstUse { registration_id, known }
        = resolve().await?.unwrap().deployments
    else {
        panic!("expected trust-on-first-use policy");
    };
    assert!(known.is_empty());

    registration::remember_deployment(&db, registration_id, "3").await?;
    // Remembering the same ID again must not create a duplicate.
    registration::remember_deployment(&db, registration_id, "3").await?;
    let DeploymentPolicy::TrustOnFirstUse { known, .. }
        = resolve().await?.unwrap().deployments
    else {
        panic!("expected trust-on-first-use policy");
    };
    assert_eq!(known, vec!["3"]);

    Ok(())
}
