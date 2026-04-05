/**
 * Fixture for D10 Cross-Service — API service owns 'orders' table.
 */

import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function createOrder(userId: string, amount: number) {
  await pool.query(
    'INSERT INTO orders (user_id, amount) VALUES ($1, $2)',
    [userId, amount]
  );
}
