-- Demo database schema for AegisNet victim application
-- Tables are populated by demo-api at startup (in-memory SQLite equivalent
-- on the API side); this schema exists so the postgres container starts
-- with a realistic structure and the eBPF agent sees real DB connections.

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    price       NUMERIC(10,2) NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 100,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS orders (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    quantity    INTEGER NOT NULL,
    total       NUMERIC(10,2) NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_orders_user ON orders (user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);

-- Seed minimal data
INSERT INTO users (username, email, role) VALUES
    ('alice', 'alice@example.com', 'admin'),
    ('bob', 'bob@example.com', 'user'),
    ('charlie', 'charlie@example.com', 'user')
ON CONFLICT DO NOTHING;

INSERT INTO products (name, price, stock) VALUES
    ('Widget A', 29.99, 150),
    ('Widget B', 49.99, 80),
    ('Gadget X', 99.99, 45)
ON CONFLICT DO NOTHING;
