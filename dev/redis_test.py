import json
import redis

r = redis.Redis(host="redis-lmp.messner.click")
for redis_key in r.keys():
    namespace = redis_key.decode("utf-8").split(":")[0]
    values = json.loads(r.get(redis_key))
    # print(namespace)
    if namespace == "mac":
        if len(values["id"].split(":")) != 6:
            print(f"wrong namespace for {namespace}, deleting entry")
            print(values)
            r.delete(redis_key)
    elif namespace == "ipv4":
        if len(values["id"].split(".")) != 4:
            print(f"wrong namespace for {namespace}, deleting entry")
            print(values)
            r.delete(redis_key)
    elif namespace == "ipv6":
        pass
        # r.delete(redis_key)
    else:
        print(f"unknown namespace {namespace}")
        print(values)
        r.delete(redis_key)
    # print(json.loads(r.get(redis_key)))
