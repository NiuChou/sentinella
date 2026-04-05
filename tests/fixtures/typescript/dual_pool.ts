/**
 * Fixture for D8 Dual-Pool Detection — TypeScript patterns.
 */

import { Pool } from 'pg';

// --- D8: Dual pool pattern ---

// Restricted pool (RLS-aware) for user-facing routes
const rlsPool = new Pool({ connectionString: process.env.DATABASE_URL_APP });

// Admin pool for workers/migrations
const adminPool = new Pool({ connectionString: process.env.DATABASE_URL_ADMIN });

// WRONG: API handler using admin pool — D8 should flag
export async function getUserProfile(req: Request, res: Response) {
  const { rows } = await adminPool.query(
    'SELECT * FROM users WHERE id = $1',
    [req.params.id]
  );
  return res.json(rows[0]);
}

// CORRECT: API handler using restricted pool
export async function getUserSessions(req: Request, res: Response) {
  const { rows } = await rlsPool.query(
    'SELECT * FROM sessions WHERE user_id = $1',
    [req.user.id]
  );
  return res.json(rows);
}

// OK: Worker using admin pool (expected)
export async function cleanupExpiredSessions() {
  await adminPool.query('DELETE FROM sessions WHERE expires_at < NOW()');
}
