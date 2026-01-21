import redis
from django.conf import settings

redis_client = redis.StrictRedis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    password=settings.REDIS_PASSWORD,
    db=0,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
    retry_on_timeout=True,
)


def test_redis_connection():
    try:
        redis_client.ping()
        return True
    except redis.ConnectionError:
        return False
