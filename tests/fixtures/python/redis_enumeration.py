"""Fixture for D9 Redis Key Enumeration Risk — Python patterns."""

import redis

redis_client = redis.Redis()


# BAD: session_id without user_id prefix — D9 should flag
def save_session_state(session_id: str, state_data: str) -> None:
    """Redis key uses session_id without user_id prefix — enumerable."""
    redis_client.set(f"session:state:{session_id}", state_data, ex=3600)


# BAD: session-scoped key without user scope — D9 should flag
def save_session_factor(session_id: str, factor: str) -> None:
    """Another session-only key pattern."""
    redis_client.set(f"session:{session_id}:factor", factor, ex=1800)


# GOOD: user_id prefix before session_id — D9 should NOT flag
def save_user_session(user_id: str, session_id: str, data: str) -> None:
    """User-scoped key with session — safe pattern."""
    redis_client.set(f"user:{user_id}:session:{session_id}", data, ex=3600)


# GOOD: user-scoped key, no session — D9 should NOT flag
def save_user_preference(user_id: str, prefs: str) -> None:
    """User-only key — safe."""
    redis_client.set(f"user:prefs:{user_id}", prefs)


# BAD: sid variant without user prefix — D9 should flag
def cache_session_token(sid: str, token: str) -> None:
    """Using sid abbreviation."""
    redis_client.set(f"auth:sid:{sid}:token", token, ex=900)
