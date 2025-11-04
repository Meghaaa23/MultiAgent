# agents/redis_manager.py
import redis, json, os, logging

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def set_agent_state(agent_name, state_dict):
    key = f"agent:{agent_name}:state"
    redis_client.set(key, json.dumps(state_dict))
    logger.info(f"[Redis] Set {key} -> {state_dict}")

def get_agent_state(agent_name):
    key = f"agent:{agent_name}:state"
    val = redis_client.get(key)
    return json.loads(val) if val else None

def push_task(queue_name, task_data):
    redis_client.lpush(f"queue:{queue_name}", json.dumps(task_data))

def pop_task(queue_name, block=False, timeout=0):
    key = f"queue:{queue_name}"
    result = redis_client.brpop(key, timeout=timeout) if block else redis_client.rpop(key)
    if result:
        _, task_json = result
        return json.loads(task_json)
    return None

def publish_event(channel, message):
    redis_client.publish(channel, message)

def subscribe_channel(channel):
    pubsub = redis_client.pubsub()
    pubsub.subscribe(channel)
    return pubsub
