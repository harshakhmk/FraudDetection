import redis
import json

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

def cache_analysis_result(user_id, analysis_result):
    redis_client.setex(f'analysis_result:{user_id}', 3600, json.dumps(analysis_result))

def get_cached_analysis_result(user_id):
    cached_result = redis_client.get(f'analysis_result:{user_id}')
    if cached_result:
        return json.loads(cached_result.decode('utf-8'))
    return None

def delete_key_from_redis(document_key):
    redis_client.delete(document_key)