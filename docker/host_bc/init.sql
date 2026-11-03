CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
);

INSERT INTO secrets (name, value)
VALUES ('db_admin_flag', 'db_admin_flag{cart_r0e_verified_2026}')
ON CONFLICT (name) DO NOTHING;
