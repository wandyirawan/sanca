-- Authorization code OAuth2 (alur authorization_code + PKCE).
--
-- Yang disimpan hanya SHA-256 hex dari kode. Nilai aslinya cuma hidup sekali:
-- dikirim ke client lewat query `?code=` pada redirect, lalu hilang. Kalau
-- tabel ini bocor, kode yang ada di dalamnya tidak bisa ditukar menjadi token.
--
-- `consumed_at` dipakai sebagai penanda sekali pakai, bukan DELETE: barisnya
-- tetap ada sebentar sebagai bukti audit, dan `UPDATE ... WHERE consumed_at IS
-- NULL RETURNING` membuat dua request bersamaan tidak bisa sama-sama berhasil.
CREATE TABLE oauth_codes (
    code_hash        text PRIMARY KEY,
    app_id           uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id       uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri     text NOT NULL,
    scope            text[] NOT NULL DEFAULT '{}',
    code_challenge   text,
    challenge_method text,
    expires_at       timestamptz NOT NULL,
    consumed_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON oauth_codes (app_id);
CREATE INDEX ON oauth_codes (expires_at);
