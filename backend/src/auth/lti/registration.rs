//! LTI Dynamic Registration: platforms register themselves at runtime instead
//! of being copied field-by-field into `[[auth.lti.platforms]]`. This module
//! holds both the registration protocol (`/~lti/register`) and the storage
//! (`lti_registrations` table) plus the combined platform lookup.

use std::{borrow::Cow, collections::BTreeMap};

use hyper::{Method, Request, StatusCode, body::Incoming, header};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::{
    auth::config::{LtiPlatform, LtiUsernameSource},
    db,
    http::{self, Context, Response},
    prelude::*,
    util::{ByteBody, HttpUrl, download_body_limited},
};

use super::deeplink::{html_escape, token_response};
use super::random_token;


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
/// platform" and must be rejected by the caller. The DB is only consulted
/// (and a connection only acquired) when the config has no match, so
/// config-only deployments keep working without the DB.
pub(crate) async fn resolve_platform(
    ctx: &Context,
    issuer: &str,
    client_id: Option<&str>,
) -> Result<Option<ResolvedPlatform>, Response> {
    let config = &ctx.config.auth.lti;
    let from_config = match client_id {
        Some(client_id) => config.find_platform(issuer, client_id),
        None => config.find_platform_by_issuer(issuer),
    };
    if let Some(platform) = from_config {
        return Ok(Some(ResolvedPlatform::from_config(platform)));
    }

    let db = db::get_conn_or_service_unavailable(&ctx.db_pool).await?;
    find_registration(&db, issuer, client_id).await.map_err(|e| {
        error!("LTI platform lookup failed: {e:#}");
        http::response::internal_server_error()
    })
}

/// The DB half of [`resolve_platform`]: looks up a dynamic registration.
pub(crate) async fn find_registration(
    db: &tokio_postgres::Client,
    issuer: &str,
    client_id: Option<&str>,
) -> Result<Option<ResolvedPlatform>> {
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

/// Upper bound for the platform's OpenID configuration document. Real ones are
/// a few KiB; anything bigger is not a configuration document.
const CONFIG_SIZE_LIMIT: usize = 256 * 1024;

/// Handles `GET /~lti/register`: IMS Dynamic Registration. The LMS admin
/// enters `https://<tobira>/~lti/register?secret=<…>` as the registration URL;
/// the platform opens it (in the admin's browser) with `openid_configuration`
/// and `registration_token` appended. Tobira fetches the platform's
/// configuration, POSTs its own client registration, stores the result, and
/// tells the platform's dialog to close.
pub(crate) async fn handle_register(req: Request<Incoming>, ctx: &Context) -> Response {
    let lti = &ctx.config.auth.lti;
    let (true, Some(secret)) = (lti.enabled, &lti.registration_secret) else {
        return http::response::not_found();
    };

    let query = req.uri().query().unwrap_or("");
    let params: BTreeMap<Cow<str>, Cow<str>>
        = form_urlencoded::parse(query.as_bytes()).collect();
    let get = |key: &str| params.get(key).map(|s| s.trim()).filter(|s| !s.is_empty());

    let secret_ok = get("secret").is_some_and(|given| {
        aws_lc_rs::constant_time::verify_slices_are_equal(
            given.as_bytes(),
            secret.expose_secret().as_bytes(),
        ).is_ok()
    });
    if !secret_ok {
        warn!("LTI registration attempt with missing or wrong secret");
        return error_page(StatusCode::FORBIDDEN, "The registration secret is wrong. \
            Please verify the registration URL with the Tobira administrator.");
    }

    let Some(config_url) = get("openid_configuration") else {
        return error_page(StatusCode::BAD_REQUEST, "The platform did not send its \
            'openid_configuration' — this URL must be opened by the LMS, not directly.");
    };
    let registration_token = get("registration_token");

    // ----- Fetch and check the platform's configuration --------------------------------------
    let platform = match fetch_platform_config(config_url, ctx).await {
        Ok(platform) => platform,
        Err(e) => {
            warn!("LTI registration: fetching platform configuration failed: {e:#}");
            return error_page(StatusCode::BAD_GATEWAY, &format!(
                "Could not fetch the platform configuration: {e:#}",
            ));
        }
    };

    // ----- Register Tobira at the platform ---------------------------------------------------
    let (client_id, deployment_id) = match register_at_platform(
        &platform,
        registration_token,
        ctx,
    ).await {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!("LTI registration: platform rejected our registration: {e:#}");
            return error_page(StatusCode::BAD_GATEWAY, &format!(
                "The platform rejected the registration: {e:#}",
            ));
        }
    };

    // ----- Store & close the dialog -----------------------------------------------------------
    let db = match db::get_conn_or_service_unavailable(&ctx.db_pool).await {
        Ok(db) => db,
        Err(response) => return response,
    };
    let stored = upsert_registration(&db, &platform, &client_id, deployment_id.as_deref()).await;
    if let Err(e) = stored {
        error!("LTI registration: failed to store registration: {e:#}");
        return http::response::internal_server_error();
    }

    info!(
        "LTI dynamic registration: registered platform '{}' (client_id '{client_id}')",
        platform.issuer,
    );
    close_dialog_page()
}

/// The subset of the platform's OpenID configuration Dynamic Registration
/// needs. LTI-specific values live under the spec claim.
#[derive(Debug, Deserialize)]
pub(super) struct PlatformConfig {
    issuer: String,
    authorization_endpoint: HttpUrl,
    registration_endpoint: HttpUrl,
    jwks_uri: HttpUrl,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti-platform-configuration")]
    lti: Option<LtiPlatformConfigurationClaim>,
}

#[derive(Debug, Deserialize)]
struct LtiPlatformConfigurationClaim {
    product_family_code: Option<String>,
}

impl PlatformConfig {
    fn platform_name(&self) -> Option<&str> {
        self.lti.as_ref()?.product_family_code.as_deref()
    }
}

/// Requires strict `https` — deliberately NOT `ensure_secure_no_fragment`,
/// whose `#allow-insecure` escape hatch is meant for admin-*configured* URLs.
/// Registration URLs come from the network.
fn ensure_https(url: &HttpUrl, what: &str) -> Result<()> {
    anyhow::ensure!(url.scheme() == "https", "{what} must be an https URL");
    Ok(())
}

async fn fetch_platform_config(config_url: &str, ctx: &Context) -> Result<PlatformConfig> {
    let url: HttpUrl = config_url.parse()
        .map_err(|e| anyhow!("'openid_configuration' is not a valid URL: {e}"))?;
    ensure_https(&url, "'openid_configuration'")?;

    let uri = url.as_str().parse().context("unusable configuration URL")?;
    let response = ctx.http_client.get(uri).await
        .context("platform configuration not reachable")?;
    if !response.status().is_success() {
        bail!("platform configuration returned status {}", response.status());
    }
    let body = download_body_limited(response.into_body(), CONFIG_SIZE_LIMIT).await
        .context("could not read platform configuration")?;
    let platform: PlatformConfig = serde_json::from_slice(&body)
        .context("could not parse platform configuration")?;

    // The issuer is pinned to the configuration URL's host. The three endpoint
    // URLs inside the (issuer-pinned) document are checked for https only, not
    // for their host: multi-host platforms exist, and whoever controls the
    // issuer host could serve any content on it anyway — the secret holder is
    // trusted to point Tobira at a real platform.
    check_issuer(&platform.issuer, &url)?;
    ensure_https(&platform.registration_endpoint, "registration endpoint")?;
    ensure_https(&platform.jwks_uri, "jwks_uri")?;
    ensure_https(&platform.authorization_endpoint, "authorization endpoint")?;

    Ok(platform)
}

/// The configuration URL was given by the caller — the `issuer` inside it must
/// belong to the same host, so nobody can register "on behalf of" a foreign
/// issuer by serving a crafted configuration document.
fn check_issuer(issuer: &str, config_url: &HttpUrl) -> Result<()> {
    let issuer_host = url::Url::parse(issuer).ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    let config_host = url::Url::parse(config_url.as_str()).ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    match (issuer_host, config_host) {
        (Some(a), Some(b)) if a == b => Ok(()),
        _ => bail!("the configuration's issuer does not match the configuration URL's host"),
    }
}

/// Builds the client registration Tobira submits: everything the manual Moodle
/// checklist used to contain, including the `username` custom parameter and
/// Deep Linking support.
pub(super) fn registration_request(base: &str, client_name: &str) -> serde_json::Value {
    let domain = url::Url::parse(base).ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    serde_json::json!({
        "application_type": "web",
        "response_types": ["id_token"],
        "grant_types": ["client_credentials", "implicit"],
        "initiate_login_uri": format!("{base}/~lti/login"),
        "redirect_uris": [format!("{base}/~lti/launch")],
        "client_name": client_name,
        "jwks_uri": format!("{base}/~lti/jwks"),
        "token_endpoint_auth_method": "private_key_jwt",
        "https://purl.imsglobal.org/spec/lti-tool-configuration": {
            "domain": domain,
            "target_link_uri": format!("{base}/~lti/launch"),
            "custom_parameters": { "username": "$User.username" },
            "claims": ["iss", "sub", "name", "email"],
            "messages": [
                { "type": "LtiResourceLinkRequest" },
                {
                    "type": "LtiDeepLinkingRequest",
                    "target_link_uri": format!("{base}/~lti/launch"),
                },
            ],
        },
    })
}

/// The subset of the platform's registration response we need.
#[derive(Debug, Deserialize)]
pub(super) struct RegistrationResponse {
    client_id: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti-tool-configuration")]
    lti: Option<ToolConfigurationClaim>,
}

#[derive(Debug, Deserialize)]
struct ToolConfigurationClaim {
    deployment_id: Option<String>,
}

async fn register_at_platform(
    platform: &PlatformConfig,
    registration_token: Option<&str>,
    ctx: &Context,
) -> Result<(String, Option<String>)> {
    let payload = registration_request(
        &ctx.config.general.tobira_url.to_string(),
        ctx.config.general.site_title.default(),
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(platform.registration_endpoint.as_str())
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = registration_token {
        // The token comes from the query string; reject values that are not a
        // valid header (e.g. embedded control characters) instead of panicking
        // on `body()` below.
        let value = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow!("'registration_token' contains invalid characters"))?;
        request = request.header(header::AUTHORIZATION, value);
    }
    let request = request
        .body(ByteBody::new(payload.to_string().into()))
        .expect("failed to build registration request");

    let response = ctx.http_client.request(request).await
        .context("registration endpoint not reachable")?;
    let status = response.status();
    let body = download_body_limited(response.into_body(), CONFIG_SIZE_LIMIT).await
        .context("could not read registration response")?;
    if !status.is_success() {
        bail!(
            "registration endpoint returned status {status}: {}",
            String::from_utf8_lossy(&body[..body.len().min(500)]),
        );
    }
    let response: RegistrationResponse = serde_json::from_slice(&body)
        .context("could not parse registration response")?;

    let deployment_id = response.lti.and_then(|lti| lti.deployment_id);
    Ok((response.client_id, deployment_id))
}

/// Stores a registration; registering the same platform again updates it
/// (admins do click the button twice). Already-known deployment IDs survive.
async fn upsert_registration(
    db: &tokio_postgres::Client,
    platform: &PlatformConfig,
    client_id: &str,
    deployment_id: Option<&str>,
) -> Result<()> {
    let deployment_ids: Vec<&str> = deployment_id.into_iter().collect();
    db.execute(
        "insert into lti_registrations \
            (issuer, client_id, auth_login_url, keyset_url, deployment_ids, platform_name) \
            values ($1, $2, $3, $4, $5, $6) \
            on conflict (issuer) do update set \
                client_id = excluded.client_id, \
                auth_login_url = excluded.auth_login_url, \
                keyset_url = excluded.keyset_url, \
                platform_name = excluded.platform_name, \
                deployment_ids = array( \
                    select distinct unnest( \
                        lti_registrations.deployment_ids || excluded.deployment_ids))",
        &[
            &platform.issuer,
            &client_id,
            &platform.authorization_endpoint.as_str(),
            &platform.jwks_uri.as_str(),
            &deployment_ids,
            &platform.platform_name(),
        ],
    ).await.context("failed to upsert lti_registrations row")?;
    Ok(())
}

/// The page ending a successful registration: it asks the platform's dialog to
/// close (the IMS-specified `postMessage`), with a visible fallback text.
fn close_dialog_page() -> Response {
    let nonce = random_token();
    let html = format!(
        "<!DOCTYPE html>\
        <html lang=\"en\">\
        <head><meta charset=\"utf-8\"><title>Registration complete</title></head>\
        <body>\
            <p>Tobira is registered. You can close this dialog.</p>\
            <script nonce=\"{nonce}\">\
                (window.opener || window.parent).postMessage(\
                    {{subject: \"org.imsglobal.lti.close\"}}, \"*\");\
            </script>\
        </body>\
        </html>",
    );
    token_response()
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header("Content-Security-Policy", format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'",
        ))
        .body(html.into())
        .unwrap()
}

/// A human-readable error page: the LMS admin sees this directly inside the
/// registration dialog.
fn error_page(status: StatusCode, message: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html>\
        <html lang=\"en\">\
        <head><meta charset=\"utf-8\"><title>Registration failed</title></head>\
        <body><h1>Tobira: registration failed</h1><p>{}</p></body>\
        </html>",
        html_escape(message),
    );
    token_response()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header("Content-Security-Policy", "default-src 'none'; base-uri 'none'")
        .body(html.into())
        .unwrap()
}

/// Remembers a newly seen deployment ID of a dynamic registration. Idempotent:
/// concurrent first launches of the same deployment do not create duplicates.
pub(crate) async fn remember_deployment(
    db: &tokio_postgres::Client,
    registration_id: i64,
    deployment_id: &str,
) -> Result<()> {
    db.execute(
        "update lti_registrations \
            set deployment_ids = array_append(deployment_ids, $2) \
            where id = $1 and not ($2 = any(deployment_ids))",
        &[&registration_id, &deployment_id],
    ).await.context("failed to record deployment id")?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like Moodle's `/mod/lti/openid-configuration.php` response
    /// (subset). OP1 in the spec: verify against the real Moodle during E2E.
    const MOODLE_CONFIG: &str = r#"{
        "issuer": "https://moodle.example.org",
        "token_endpoint": "https://moodle.example.org/mod/lti/token.php",
        "authorization_endpoint": "https://moodle.example.org/mod/lti/auth.php",
        "registration_endpoint": "https://moodle.example.org/mod/lti/openid-registration.php",
        "jwks_uri": "https://moodle.example.org/mod/lti/certs.php",
        "scopes_supported": ["openid"],
        "https://purl.imsglobal.org/spec/lti-platform-configuration": {
            "product_family_code": "moodle",
            "version": "5.1",
            "messages_supported": [
                {"type": "LtiResourceLinkRequest"},
                {"type": "LtiDeepLinkingRequest"}
            ]
        }
    }"#;

    #[test]
    fn from_config_pins_the_deployment_id() {
        let platform = LtiPlatform {
            issuer: "https://moodle.example.org".into(),
            client_id: "from-config".into(),
            deployment_id: "1".into(),
            auth_login_url: "https://lms.example.org/auth".parse().unwrap(),
            keyset_url: "https://lms.example.org/jwks".parse().unwrap(),
            username_source: LtiUsernameSource::default(),
        };
        let resolved = ResolvedPlatform::from_config(&platform);
        assert_eq!(resolved.client_id, "from-config");
        assert_eq!(resolved.username_source, LtiUsernameSource::PreferredUsername);
        assert!(matches!(resolved.deployments, DeploymentPolicy::Fixed(ref d) if d == "1"));
    }

    #[test]
    fn platform_config_parses_and_issuer_check_works() {
        let config: PlatformConfig = serde_json::from_str(MOODLE_CONFIG).unwrap();
        assert_eq!(config.issuer, "https://moodle.example.org");
        assert_eq!(config.platform_name(), Some("moodle"));
        assert_eq!(config.jwks_uri.as_str(), "https://moodle.example.org/mod/lti/certs.php");

        let config_url: HttpUrl = "https://moodle.example.org/mod/lti/openid-configuration.php"
            .parse().unwrap();
        assert!(check_issuer(&config.issuer, &config_url).is_ok());
        // A crafted configuration served from elsewhere must not be able to
        // claim a foreign issuer.
        let foreign: HttpUrl = "https://evil.example.org/config".parse().unwrap();
        assert!(check_issuer(&config.issuer, &foreign).is_err());
        assert!(check_issuer("not a url", &config_url).is_err());
    }

    #[test]
    fn registration_request_covers_the_manual_checklist() {
        let payload = registration_request("https://tobira.example.org", "Tobira");
        assert_eq!(
            payload["redirect_uris"][0],
            "https://tobira.example.org/~lti/launch",
        );
        assert_eq!(
            payload["initiate_login_uri"],
            "https://tobira.example.org/~lti/login",
        );
        assert_eq!(payload["jwks_uri"], "https://tobira.example.org/~lti/jwks");

        let tool = &payload["https://purl.imsglobal.org/spec/lti-tool-configuration"];
        assert_eq!(tool["domain"], "tobira.example.org");
        // The two pieces whose absence cost us the most debugging time when
        // registering manually:
        assert_eq!(tool["custom_parameters"]["username"], "$User.username");
        assert!(tool["messages"].as_array().unwrap().iter()
            .any(|m| m["type"] == "LtiDeepLinkingRequest"));
    }

    #[test]
    fn registration_response_parses_with_and_without_deployment() {
        let with: RegistrationResponse = serde_json::from_str(r#"{
            "client_id": "pjeSqQewkRlOJYR",
            "response_types": ["id_token"],
            "https://purl.imsglobal.org/spec/lti-tool-configuration": {
                "deployment_id": "4",
                "version": "1.3.0"
            }
        }"#).unwrap();
        assert_eq!(with.client_id, "pjeSqQewkRlOJYR");
        assert_eq!(with.lti.and_then(|l| l.deployment_id).as_deref(), Some("4"));

        let without: RegistrationResponse
            = serde_json::from_str(r#"{"client_id": "abc"}"#).unwrap();
        assert_eq!(without.client_id, "abc");
        assert!(without.lti.is_none());
    }
}
