/**
 * Fixture for D10 Cross-Service — Worker service directly queries 'users' table.
 * This SHOULD be flagged by D10 — worker should use API, not direct table access.
 */

import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// WRONG: Worker directly reads 'users' table owned by API service — D10 should flag
export async function cleanupInactiveUsers() {
  const { rows } = await pool.query(
    'SELECT id FROM users WHERE last_login < NOW() - INTERVAL \'90 days\''
  );
  for (const row of rows) {
    await pool.query('DELETE FROM users WHERE id = $1', [row.id]);
  }
}

// WRONG: Worker directly reads 'orders' table owned by API service — D10 should flag
export async function generateReport() {
  const { rows } = await pool.query(
    'SELECT * FROM orders WHERE created_at > NOW() - INTERVAL \'30 days\''
  );
  return rows;
}
