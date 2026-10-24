-- Seed app `core` dan role sistem `superadmin` untuk app tersebut.
-- UUID ditulis literal (v7, versi dan varian valid) supaya id stabil di semua environment.

INSERT INTO apps (id, slug, name, description, kind, is_active)
VALUES (
    '0192f3a4-5b6c-7d8e-9f01-234567890abc',
    'core',
    'Sanca Core',
    'Aplikasi inti: konsol admin dan penerbit token.',
    'web',
    true
);

INSERT INTO roles (id, app_id, key, name, description, is_system)
VALUES (
    '0192f3a4-5b6c-7d8e-9f01-234567890abd',
    '0192f3a4-5b6c-7d8e-9f01-234567890abc',
    'superadmin',
    'Superadmin',
    'Role sistem dengan akses penuh di app core.',
    true
);
