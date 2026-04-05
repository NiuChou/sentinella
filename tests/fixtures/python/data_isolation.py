"""Fixture for S12 Data Isolation Audit — Python patterns."""

import os
import json
import redis
from sqlalchemy import text

# --- D1: Ghost table detection (factor_results is never written to) ---
# This file writes to sessions and drp_transactions but NOT factor_results

async def save_session(db, session_id, user_id, data):
    """Writes to sessions table — should be detected as DbWriteRef."""
    await db.execute(
        text("INSERT INTO sessions (id, user_id, data) VALUES (:id, :uid, :data)"),
        {"id": session_id, "uid": user_id, "data": json.dumps(data)},
    )
    await db.commit()


async def update_session_pointer(db, session_id, factor, index):
    """Updates sessions table — should be detected as DbWriteRef."""
    await db.execute(
        text("UPDATE sessions SET current_factor = :f, factor_index = :i WHERE id = :sid"),
        {"f": factor, "i": index, "sid": session_id},
    )
    await db.commit()


# --- D2: RLS activation (SET LOCAL) ---

async def rls_enabled_query(db, user_id):
    """Properly activates RLS context — should be detected as RlsContextRef."""
    await db.execute(
        text("SET LOCAL app.current_user_id = :uid"),
        {"uid": user_id},
    )
    result = await db.execute(text("SELECT * FROM sessions"))
    return result.fetchall()


# --- D4: Missing ownership filter ---

async def delete_without_owner(db, session_id):
    """DELETE without user_id filter — D4 should flag this."""
    await db.execute(
        text("DELETE FROM sessions WHERE id = :sid"),
        {"sid": session_id},
    )


async def select_without_owner(db, template_id):
    """SELECT without user_id filter — D5 should flag this."""
    result = await db.execute(
        text("SELECT * FROM templates WHERE id = :tid"),
        {"tid": template_id},
    )
    return result.fetchone()


# --- D6: Redis cache-only pattern ---

redis_client = redis.Redis()


def save_factor_to_redis_only(session_id, factor, result_data):
    """Writes to Redis with TTL but no DB write — D6 should flag this."""
    key = f"session:state:{session_id}"
    redis_client.set(key, json.dumps(result_data), ex=86400)


def save_drp_balance(user_id, balance):
    """DRP balance in Redis only — D6 should flag this."""
    redis_client.set(f"drp:balance:{user_id}", str(balance))


def get_drp_balance(user_id):
    """Redis read — should be detected as RedisOp::Read."""
    return redis_client.get(f"drp:balance:{user_id}")


def delete_session_cache(session_id):
    """Redis delete — should be detected as RedisOp::Delete."""
    redis_client.delete(f"session:state:{session_id}")


# --- D7: Hardcoded credentials ---

MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin123"

DATABASE_PASSWORD = "dev-postgres-password"

# This should NOT be flagged (env var reference):
API_KEY = os.getenv("EXTERNAL_API_KEY", "")
