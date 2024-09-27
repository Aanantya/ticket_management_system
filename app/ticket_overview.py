import redis
from app.queries import get_active_tickets_count, get_resolved_tickets_count, get_closed_tickets_count, get_active_agents_count

# Initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Utility function to get data from cache or source
def get_data_from_cache_or_source(key, fetch_function, expiry=300):
    """Fetch data from Redis cache, or fallback to database/source if not found."""
    print(key, fetch_function, expiry)
    try:
        # Attempt to get the data from Redis cache
        cached_value = redis_client.get(key)
        if cached_value is not None:
            print('cached_value:', cached_value)
            # If data is found in the cache, return it
            return int(cached_value.decode('utf-8'))
        
        # If cache miss, fetch the data from the source function
        value = fetch_function()
        print('value', value)
        # Store the fetched data in Redis with an expiry time
        redis_client.setex(key, expiry, value)
        return value
    
    except Exception as e:
        print(f"Error fetching {key} from cache: {e}")
        # If any error occurs, fallback to source function without caching
        return fetch_function()
