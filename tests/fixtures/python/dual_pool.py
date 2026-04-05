"""Fixture for D8 Dual-Pool Detection — Python patterns."""

import os
from sqlalchemy import create_engine

# --- D8: Dual pool pattern (perseworks rlspool) ---

# Restricted pool for user-facing code (should use this)
app_engine = create_engine(os.getenv("DATABASE_URL_APP"))

# Admin pool for workers/migrations (should NOT be used in handlers)
admin_engine = create_engine(os.getenv("DATABASE_URL_ADMIN"))


# WRONG: Route handler using admin pool — D8 should flag this
async def get_user_profile(request):
    """User-facing endpoint using admin pool."""
    async with admin_engine.connect() as conn:
        result = await conn.execute(
            "SELECT * FROM users WHERE id = :id", {"id": request.user_id}
        )
        return result.fetchone()


# CORRECT: Route handler using restricted pool
async def get_user_sessions(request):
    """User-facing endpoint using restricted pool."""
    async with app_engine.connect() as conn:
        result = await conn.execute(
            "SELECT * FROM sessions WHERE user_id = :uid",
            {"uid": request.user_id},
        )
        return result.fetchall()


# OK: Worker using admin pool (expected)
async def cleanup_expired_sessions():
    """Background worker — admin pool is acceptable."""
    async with admin_engine.connect() as conn:
        await conn.execute("DELETE FROM sessions WHERE expires_at < NOW()")
