-- Skema awal Sanca: identitas, app, sesi, RBAC, audit, signing key.
-- Sumber: AGENTS.md bagian 6. Perubahan yang disengaja dari draf: hanya citext yang
-- diaktifkan; pgcrypto dan uuid-ossp tidak dipakai karena semua id dibuat di aplikasi
-- sebagai UUID v7.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_status AS ENUM ('active', 'disabled', 'pending');
CREATE TYPE app_kind    AS ENUM ('web', 'spa', 'service', 'cli');
CREATE TYPE actor_type  AS ENUM ('user', 'service', 'system');

CREATE TABLE users (
    id             uuid PRIMARY KEY,
    email          citext UNIQUE NOT NULL,
    password_hash  text   NOT NULL,
    pepper_version smallint NOT NULL DEFAULT 1,
    display_name   text   NOT NULL DEFAULT '',
    status         user_status NOT NULL DEFAULT 'active',
    is_superadmin  boolean NOT NULL DEFAULT false,
    token_version  integer NOT NULL DEFAULT 0,   -- bump = revoke semua akses instan
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_attributes (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        text NOT NULL,
    value      jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

CREATE TABLE apps (
    id               uuid PRIMARY KEY,
    slug             text UNIQUE NOT NULL,        -- klaim `aud`
    name             text NOT NULL,
    description      text NOT NULL DEFAULT '',
    kind             app_kind NOT NULL DEFAULT 'web',
    redirect_uris    text[] NOT NULL DEFAULT '{}',
    access_ttl_secs  integer NOT NULL DEFAULT 900,
    refresh_ttl_secs integer NOT NULL DEFAULT 2592000,
    is_active        boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_credentials (
    id                 uuid PRIMARY KEY,
    app_id             uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id          text UNIQUE NOT NULL,
    client_secret_hash text NOT NULL,
    pepper_version     smallint NOT NULL DEFAULT 1,
    name               text NOT NULL DEFAULT 'default',
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app_credentials (app_id);

CREATE TABLE sessions (
    id           uuid PRIMARY KEY,                -- klaim `sid`
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id       uuid NOT NULL REFERENCES apps(id),
    refresh_hash text NOT NULL UNIQUE,
    user_agent   text NOT NULL DEFAULT '',
    ip           inet,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON sessions (user_id);
CREATE INDEX ON sessions (app_id);
CREATE INDEX ON sessions (expires_at);

CREATE TABLE roles (
    id          uuid PRIMARY KEY,
    app_id      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

CREATE TABLE permissions (
    id          uuid PRIMARY KEY,
    app_id      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,   -- dari registry, tidak bisa dihapus
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_events (
    id             bigserial PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    app_id         uuid REFERENCES apps(id),
    app_slug       text NOT NULL,
    actor_type     actor_type NOT NULL,
    actor_user_id  uuid REFERENCES users(id),
    actor_label    text NOT NULL DEFAULT '',
    session_id     uuid,
    action         text NOT NULL,
    resource_type  text NOT NULL DEFAULT '',
    resource_id    text NOT NULL DEFAULT '',
    permission_key text,
    method         text NOT NULL DEFAULT '',
    path           text NOT NULL DEFAULT '',
    status_code    integer,
    ip             inet,
    user_agent     text NOT NULL DEFAULT '',
    request_id     text NOT NULL DEFAULT '',
    metadata       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON audit_events (app_id, occurred_at DESC);
CREATE INDEX ON audit_events (actor_user_id, occurred_at DESC);
CREATE INDEX ON audit_events (occurred_at DESC);

-- DB hanya menyimpan public key. Private key hidup di env/file (lihat AGENTS.md bagian 7).
CREATE TABLE signing_keys (
    kid        text PRIMARY KEY,
    alg        text NOT NULL DEFAULT 'RS256',
    public_pem text NOT NULL,
    is_active  boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
