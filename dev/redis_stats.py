import json
import time
import redis
import mac_vendor_lookup

SUBNET = "192.168.1"
NAMESPACE = "mac"
NOW = int(time.time())

def get_data(namespace_filter):
    data = {}
    r = redis.Redis(host="redis-lmp.messner.click")
    for redis_key in r.keys():
        namespace = redis_key.decode("utf-8").split(":")[0]
        values = json.loads(r.get(redis_key))
        if namespace_filter == namespace:
            data[values["id"]] = values
    return data


mac_data = get_data("mac")
ip_data = get_data("ipv4")
# print(ip_data)

mac_lookup = mac_vendor_lookup.MacLookup()
for key, value in sorted(mac_data.items(), key=lambda a: a[1]["id"], reverse=False):
    try:
        vendor = mac_lookup.lookup(key)
    except mac_vendor_lookup.VendorNotFoundError:
        vendor = "unknown"
    if (NOW - int(value['last_seen'])) > 60*60*24:
        active = False
    else:
        active = True
    if (NOW - int(value['first_seen'])) > 60*60*24:
        fresh = False
    else:
        fresh = True
    ip = [entry["id"] for entry in ip_data.values() if entry["mac_dst"] == key and entry["id"].startswith(SUBNET)]
    # print(ip)
    print(f"{key}\t{int(value['first_seen'])}\t{active}\t{fresh}\t{vendor}")
print(f"found {len(mac_data)} entries")
