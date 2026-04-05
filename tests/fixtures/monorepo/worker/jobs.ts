/**
 * Fixture for D10 Cross-Service — Worker service owns 'job_queue' table.
 * This should NOT be flagged — worker owns this table.
 */

import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function enqueueJob(type: string, payload: object) {
  await pool.query(
    'INSERT INTO job_queue (type, payload) VALUES ($1, $2)',
    [type, JSON.stringify(payload)]
  );
}

export async function dequeueJob() {
  const { rows } = await pool.query(
    'SELECT * FROM job_queue WHERE status = \'pending\' LIMIT 1'
  );
  return rows[0];
}
