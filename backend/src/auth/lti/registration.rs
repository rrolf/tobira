//! Runtime-registered LTI platforms (Dynamic Registration), stored in the
//! `lti_registrations` table — the counterpart to the statically configured
//! `[[auth.lti.platforms]]`.

use crate::{
    auth::config::{LtiConfig, LtiPlatform, LtiUsernameSource},
    prelude::*,
    util::HttpUrl,
};


/// The platform an incoming login/launch resolved to: either one from the
/// static config or a dynamic registration from the DB.
pub(crate) struct ResolvedPlatform {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) auth_login_url: HttpUrl,
    pub(crate) keyset_url: HttpUrl,
    pub(crate) username_source: LtiUsernameSource,
    pub(crate) deployments: DeploymentPolicy,
}

/// How deployment IDs are checked for a platform.
pub(crate) enum DeploymentPolicy {
    /// Configured platforms pin exactly one deployment ID.
    Fixed(String),

    /// Dynamic registrations cover the whole platform: deployment IDs not seen
    /// before are accepted on first use, logged, and remembered. The admin
    /// registered the platform as a whole; authenticity rests on the token
    /// signature and the `iss`/`aud` checks either way.
    TrustOnFirstUse {
        registration_id: i64,
        known: Vec<String>,
    },
}

impl ResolvedPlatform {
    fn from_config(platform: &LtiPlatform) -> Self {
        Self {
            issuer: platform.issuer.clone(),
            client_id: platform.client_id.clone(),
            auth_login_url: platform.auth_login_url.clone(),
            keyset_url: platform.keyset_url.clone(),
            username_source: platform.username_source,
            deployments: DeploymentPolicy::Fixed(platform.deployment_id.clone()),
        }
    }
}

/// Looks up the platform for `issuer` (and, if given, `client_id`): the static
/// config wins, then dynamic registrations. `Ok(None)` means "unknown
/// platform" and must be rejected by the caller.
pub(crate) async fn resolve_platform(
    db: &tokio_postgres::Client,
    config: &LtiConfig,
    issuer: &str,
    client_id: Option<&str>,
) -> Result<Option<ResolvedPlatform>> {
    let from_config = match client_id {
        Some(client_id) => config.find_platform(issuer, client_id),
        None => config.find_platform_by_issuer(issuer),
    };
    if let Some(platform) = from_config {
        return Ok(Some(ResolvedPlatform::from_config(platform)));
    }

    let row = db.query_opt(
        "select id, client_id, auth_login_url, keyset_url, deployment_ids, username_source \
            from lti_registrations \
            where issuer = $1",
        &[&issuer],
    ).await.context("failed to query lti_registrations")?;
    let Some(row) = row else {
        return Ok(None);
    };

    let registered_client_id: String = row.get(1);
    if client_id.is_some_and(|given| given != registered_client_id) {
        return Ok(None);
    }

    // These columns were written from validated values; treat rows that no
    // longer parse as "unknown platform" instead of failing the request hard.
    let parse_url = |index: usize| -> Option<HttpUrl> {
        let raw: String = row.get(index);
        raw.parse().map_err(|e| {
            warn!("lti_registrations row for '{issuer}' has unusable URL: {e}");
        }).ok()
    };
    let Some(auth_login_url) = parse_url(2) else { return Ok(None) };
    let Some(keyset_url) = parse_url(3) else { return Ok(None) };
    let username_source = LtiUsernameSource::from_db_value(&row.get::<_, String>(5))
        .unwrap_or_default();

    Ok(Some(ResolvedPlatform {
        issuer: issuer.to_owned(),
        client_id: registered_client_id,
        auth_login_url,
        keyset_url,
        username_source,
        deployments: DeploymentPolicy::TrustOnFirstUse {
            registration_id: row.get(0),
            known: row.get(4),
        },
    }))
}

/// Remembers a newly seen deployment ID of a dynamic registration.
pub(crate) async fn remember_deployment(
    db: &tokio_postgres::Client,
    registration_id: i64,
    deployment_id: &str,
) -> Result<()> {
    db.execute(
        "update lti_registrations \
            set deployment_ids = array_append(deployment_ids, $2) \
            where id = $1",
        &[&registration_id, &deployment_id],
    ).await.context("failed to record deployment id")?;
    Ok(())
}
