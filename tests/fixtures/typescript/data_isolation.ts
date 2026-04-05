/**
 * Fixture for S12 Data Isolation Audit — TypeScript patterns.
 */

import { Pool } from 'pg';
import Redis from 'ioredis';

const pool = new Pool();
const redis = new Redis();

// --- D1: DB write detection ---

export async function createUser(name: string, email: string) {
  // Should be detected as DbWriteRef (INSERT INTO users)
  await pool.query(
    `INSERT INTO users (name, email) VALUES ($1, $2)`,
    [name, email]
  );
}

export async function updateOrder(orderId: string, status: string) {
  // Should be detected as DbWriteRef (UPDATE orders)
  await pool.query(
    `UPDATE orders SET status = $1 WHERE id = $2`,
    [status, orderId]
  );
}

export async function deleteSession(sessionId: string) {
  // Should be detected as DbWriteRef (DELETE FROM sessions)
  await pool.query(`DELETE FROM sessions WHERE id = $1`, [sessionId]);
}

// --- D4: Missing ownership filter ---

export async function getOrderById(orderId: string) {
  // SELECT without user_id filter — D5 should flag this
  const result = await pool.query(
    `SELECT * FROM orders WHERE id = $1`,
    [orderId]
  );
  return result.rows[0];
}

export async function updateOrderUnsafe(orderId: string, data: any) {
  // UPDATE without user_id filter — D4 should flag this
  await pool.query(
    `UPDATE orders SET data = $1 WHERE id = $2`,
    [data, orderId]
  );
}

// --- D6: Redis cache-only ---

export async function cacheUserProfile(userId: string, profile: object) {
  // Redis SET with TTL, no DB write nearby — D6 should flag
  await redis.set(`user:profile:${userId}`, JSON.stringify(profile), 'EX', 3600);
}

export async function getUserProfile(userId: string) {
  // Redis GET — should be detected as RedisOp::Read
  return redis.get(`user:profile:${userId}`);
}

// --- D7: Hardcoded credentials ---

const config = {
  database_password: "postgres123",
  redis_secret: "redis-dev-secret",
  jwt_token: process.env.JWT_SECRET || "",  // env ref, should NOT be flagged
};

export const INTERNAL_API_KEY = "dev-internal-key-12345";

// --- D8: RLS context setting ---

export async function setRlsContext(userId: string) {
  // SET LOCAL in a template literal — should be detected as RlsContextRef
  await pool.query(`SET LOCAL app.current_user_id = '${userId}'`);
}

export async function setRlsViaConfig(tenantId: string) {
  // set_config call — should also be detected
  await pool.query(`SELECT set_config('app.current_tenant_id', $1, true)`, [tenantId]);
}
