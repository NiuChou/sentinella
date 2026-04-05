/**
 * Fixture for D10 Cross-Service — API service owns 'users' table.
 */

import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// API service writes to 'users' — this is the owner
export async function createUser(name: string, email: string) {
  await pool.query(
    'INSERT INTO users (name, email) VALUES ($1, $2)',
    [name, email]
  );
}

export async function updateUser(id: string, name: string) {
  await pool.query(
    'UPDATE users SET name = $1 WHERE id = $2',
    [name, id]
  );
}
