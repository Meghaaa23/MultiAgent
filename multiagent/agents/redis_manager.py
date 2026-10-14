"""Redis Manager - Handles state management, caching, and pub/sub messaging"""
import os
import json
import logging
import redis
from typing import Optional, Dict, Any
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

redis_client = None

def initialize_redis() -> bool:
    """Initialize Redis connection with proper error handling."""
    global redis_client

    try:
        REDIS_URL = os.getenv("REDIS_URL")

        if REDIS_URL:
            redis_client = redis.Redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            connection_info = REDIS_URL.split('@')[-1] if '@' in REDIS_URL else "Redis Cloud"
        else:
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", 6379))
            password = os.getenv("REDIS_PASSWORD", None)
            db = int(os.getenv("REDIS_DB", 0))

            redis_client = redis.Redis(
                host=host,
                port=port,
                password=password,
                db=db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            connection_info = f"{host}:{port}"

        redis_client.ping()
        logger.info(f" Redis connected successfully to {connection_info}")
        return True

    except redis.ConnectionError as e:
        logger.warning(f"  Redis connection failed: {e}")
        logger.warning("  Continuing without Redis - caching will be disabled")
        redis_client = None
        return False

    except Exception as e:
        logger.error(f" Unexpected error during Redis initialization: {e}")
        redis_client = None
        return False

initialize_redis()

def is_redis_available() -> bool:
    """Check if Redis is available and connected."""
    if redis_client is None:
        return False
    try:
        redis_client.ping()
        return True
    except Exception:
        return False

def set_agent_state(agent_name: str, state: Dict[str, Any]) -> bool:
    """Store or update an agent's current state."""
    if not is_redis_available():
        logger.debug(f"Skipping state storage for {agent_name} (Redis unavailable)")
        return False

    try:
        key = f"agent:{agent_name}:state"
        redis_client.set(key, json.dumps(state))
        logger.debug(f"Set state for {agent_name}: {state}")
        return True
    except Exception as e:
        logger.error(f"Failed to set state for {agent_name}: {e}")
        return False

def get_agent_state(agent_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve the stored state for a specific agent."""
    if not is_redis_available():
        return None

    try:
        key = f"agent:{agent_name}:state"
        val = redis_client.get(key)
        return json.loads(val) if val else None
    except Exception as e:
        logger.error(f"Failed to get state for {agent_name}: {e}")
        return None

def publish_event(channel: str, message: str) -> bool:
    """Publish a message to a Redis Pub/Sub channel."""
    if not is_redis_available():
        logger.debug(f"Skipping event publish to {channel} (Redis unavailable)")
        return False

    try:
        redis_client.publish(channel, message)
        logger.debug(f"Published event → {channel}: {message}")
        return True
    except Exception as e:
        logger.error(f"Failed to publish event to {channel}: {e}")
        return False

def cache_result(key: str, value: str, ttl: int = 3600) -> bool:
    """Cache a result temporarily with TTL (Time To Live)."""
    if not is_redis_available():
        logger.debug(f"Skipping cache for {key} (Redis unavailable)")
        return False

    try:
        redis_client.set(key, value, ex=ttl)
        logger.debug(f"Cached key {key} (TTL={ttl}s, size={len(value)} bytes)")
        return True
    except Exception as e:
        logger.error(f"Failed to cache key {key}: {e}")
        return False

def get_cached_result(key: str) -> Optional[str]:
    """Return cached value if available."""
    if not is_redis_available():
        return None

    try:
        return redis_client.get(key)
    except Exception as e:
        logger.error(f"Failed to get cached key {key}: {e}")
        return None

def delete_key(key: str) -> bool:
    """Remove a key from Redis."""
    if not is_redis_available():
        return False

    try:
        redis_client.delete(key)
        logger.debug(f"Deleted key {key}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete key {key}: {e}")
        return False

def clear_all_cache(pattern: str = "*") -> int:
    """Clear all keys matching the pattern."""
    if not is_redis_available():
        logger.warning("Cannot clear cache (Redis unavailable)")
        return 0

    try:
        keys = redis_client.keys(pattern)
        if keys:
            deleted = redis_client.delete(*keys)
            logger.info(f"Cleared {deleted} keys matching pattern '{pattern}'")
            return deleted
        return 0
    except Exception as e:
        logger.error(f"Failed to clear cache with pattern '{pattern}': {e}")
        return 0

def get_cache_stats() -> Dict[str, Any]:
    """Get statistics about cached items."""
    if not is_redis_available():
        return {"available": False, "error": "Redis unavailable"}

    try:
        info = redis_client.info()
        return {
            "available": True,
            "used_memory": info.get("used_memory_human"),
            "total_keys": redis_client.dbsize(),
            "connected_clients": info.get("connected_clients"),
            "uptime_days": info.get("uptime_in_days")
        }
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        return {"available": False, "error": str(e)}

def clear_agent_state(agent_name: str) -> bool:
    """Clear the state for a specific agent."""
    return delete_key(f"agent:{agent_name}:state")
