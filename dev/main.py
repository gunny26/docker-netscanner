#!/usr/bin/python3
import datetime
import redis
import json
import time
import threading
import scapy.all as scapy
# from scapy.all import *

BLACKLIST = ['ff:ff:ff:ff:ff:ff', ]  # list of blacklisted macs

SEEN_MACS = None  # to store mac addresses

UPDATE_INTERVAL = 1 * 60  # in seconds
DISPLAY_INTERVAL = 20  # in seconds

ACTIVE_TIMEOUT = 5 * 60  # in seconds

REDIS_HOST = "redis-lmp.messner.click"

class Harvester:
    """ collecting ip address informations """

    def __init__(self, table_id="tableid", label="some tablename"):
        self.table_id = table_id  # like mac_addresses, ip_address, etc. not spaces
        self.label = label  # human readable tablename
        self.redis = redis.Redis(host=REDIS_HOST)
        self.data = {}
        for redis_key in self.redis.keys():
            if redis_key.startswith(table_id.encode("utf-8")):
                value = json.loads(self.redis.get(redis_key))
                self.data[value["id"]] = value
        self.update_thread = threading.Thread(target=self.update_thread)
        self.update_thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def add(self, key, values=None):
        if key not in self.data:
            self.data[key] = {
                "id": key,
                "count": 0,
                "first_seen": time.time(),
                "last_seen": 0,
                "active": 1,  # redis dont like bools
            }
        self.data[key]["count"] += 1
        self.data[key]["last_seen"] = time.time()
        if values and isinstance(values, dict):
            self.data[key].update(values)

    def update_thread(self):
        """ updateting active """
        while True:
            for key in list(self.data.keys()):
                redis_key = f"{self.table_id}:{key}"

                # updating active
                if self.data[key]["last_seen"] > (time.time() - ACTIVE_TIMEOUT):
                    self.data[key]["active"] = 1
                else:
                    self.data[key]["active"] = 0

                # setting id if not already set
                if not self.data[key].get("id"):
                    self.data["id"] = key

                # self.redis.delete(redis_key)
                self.redis.set(redis_key, json.dumps(self.data[key]))  # data to redis

                # self.persistence[key] = self.data[key]  # this makes key persistent
            time.sleep(UPDATE_INTERVAL)
        self.persistence.sync()  # update persistent data and empty cache im memory

    def dump(self, only_active=None):
        """ returning COPY of data """
        return dict(self.data)

class PacketHandler(object):

    def __init__(self):
        print("paket handler started")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def handle_packet(self, pkt):
        # print(pkt.layers())  # show layers
        # print(pkt.summary())  # oneline summary
        # print(pkt.show())  # data structure
        # print(pkt.src)

        if pkt.dst.startswith("33:33:") or pkt.dst.startswith("01:00:5e:"):  # multicast ipv6 and ipv4
            return

        if (pkt.src in BLACKLIST) or (pkt.dst in BLACKLIST):  # skip if blacklisted
            return

        # mac addresses
        mac_harvester.add(pkt.src)
        mac_harvester.add(pkt.dst)

        # ipv4
        ip = pkt.getlayer("IP")
        if ip:
            # print(ip.summary())
            ip_harvester.add(ip.src, {"mac_src": pkt.src, "mac_dst": pkt.dst})
            ip_harvester.add(ip.dst, {"mac_src": pkt.src, "mac_dst": pkt.dst})

        # ipv6
        ip6 = pkt.getlayer("ipv6")
        if ip6:
            print(ip6.summary())
            ip6_harvester.add(ip6.src, {"mac_src": pkt.src, "mac_dst": pkt.dst})
            ip6_harvester.add(ip6.dst, {"mac_src": pkt.src, "mac_dst": pkt.dst})


def display_thread(harvesters):
    """ reporting """
    print(f"reporting for {harvesters}")
    while True:
        for harvester in harvesters:
            data = harvester.dump()
            active = [key for key, value in data.items() if value["active"]]
            print(f"total seen {harvester.label} {len(data)}")
            print(f"active in last {ACTIVE_TIMEOUT} s {len(active)}")
            for key, value in sorted(data.items(), key=lambda i: i[0], reverse=True):
                print(f"\t{value['id']}\t:\t{value['count']}\t{value['last_seen']}\t{value['active']}")
        time.sleep(DISPLAY_INTERVAL)


def main():
    packet_handler = PacketHandler()
    print(f"Starting scan")
    print("Scanning...")
    iface = "wlp4s0"
    print(scapy.get_if_list())

    with packet_handler as ph:
        # sniff(iface=iface, prn=ph.handle_packet, filter="arp")
        scapy.sniff(prn=ph.handle_packet)
        # scapy.sniff(prn=ph.handle_packet, filter="arp")


if __name__ == "__main__":

    with Harvester(table_id="mac", label="mac addresses") as mac_harvester:
        with Harvester(table_id="ipv4", label="ipv4 addresses") as ip_harvester:
            with Harvester(table_id="ipv6", label="ip6_addresses") as ip6_harvester:
                display_thread = threading.Thread(target=display_thread, args=([mac_harvester, ip_harvester, ip6_harvester],))
                display_thread.start()

                main()
