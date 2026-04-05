-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create orders table with schema prefix
CREATE TABLE IF NOT EXISTS public.orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending'
);

-- Enable RLS on users
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Create RLS policy on users
CREATE POLICY user_isolation ON users
    USING (id = current_user_id());

-- Grant access
GRANT SELECT, INSERT ON TABLE users TO app_role;
GRANT ALL ON TABLE public.orders TO admin_role;

-- S12: RLS policy with session variable
CREATE POLICY users_isolation_policy ON users
    FOR ALL TO app_role
    USING (user_id = current_setting('app.current_user_id', true)::uuid)
    WITH CHECK (user_id = current_setting('app.current_user_id', true)::uuid);

-- S12: FORCE RLS
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- S12: Table with ENABLE but no FORCE (for D3 detection)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_logs_isolation ON audit_logs
    FOR ALL TO app_role
    USING (user_id = current_setting('app.current_user_id', true)::uuid);
-- NOTE: no FORCE RLS on audit_logs — intentional for testing D3
