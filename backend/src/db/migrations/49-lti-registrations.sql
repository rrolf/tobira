-- LTI platforms registered at runtime via Dynamic Registration, as opposed to
-- the statically configured ones in `[[auth.lti.platforms]]`. One row per
-- platform (issuer); re-registering the same platform updates the row.

create table lti_registrations (
    id bigint primary key generated always as identity,

    -- The platform's issuer identifier, compared verbatim against the `iss`
    -- claim of launches.
    issuer text not null unique,

    -- The client ID the platform assigned to Tobira during registration.
    client_id text not null,

    -- The platform's OIDC authorization endpoint (login initiations redirect
    -- there) and its JWKS URL (launch tokens are verified against it).
    auth_login_url text not null,
    keyset_url text not null,

    -- Deployment IDs seen for this platform: from the registration response
    -- and appended as launches introduce new ones (trust-on-first-use; the
    -- registration covers the whole platform).
    deployment_ids text[] not null default '{}',

    -- Which launch claim provides the Opencast username, see the
    -- `username_source` option of `[[auth.lti.platforms]]`. Dynamic
    -- registrations register the `username` custom parameter themselves, so
    -- this is `custom` unless changed manually.
    username_source text not null default 'custom',

    -- Human-readable platform name from its OpenID configuration, if any.
    -- Purely informational (CLI listing, logs).
    platform_name text,

    created timestamp with time zone not null default now()
);
