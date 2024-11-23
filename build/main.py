#!/usr/bin/python3
import logging
import os
import sys
import time
from prometheus_client import start_http_server, Counter

# import scapy
import scapy.all as scapy

logging.basicConfig(level=logging.INFO)

EXPORTER_LOG_LEVEL = os.environ.get("EXPORTER_LOG_LEVEL", "INFO")
EXPORTER_INTERFACE = os.environ.get(
    "EXPORTER_INTERFACE",
    "wlp4s0",  # default for development
)  # None to listen on all available, if set only this one
EXPORTER_DISPLAY_INTERVAL = int(os.environ.get("EXPORTER_DISPLAY_INTERVAL", "60"))
EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "9100"))

logging.info("showing enviroment variables")
for key, value in os.environ.items():
    if key.startswith("EXPORTER_"):
        logging.info(f"{key}: {value}")

# prometheus metrics
MAC_SEEN_TOTAL = Counter(
    "netscanner_mac_seen_total",
    "Number of intervals this MAC address was seen",
    [
        "address",
    ],
)
IPV4_SEEN_TOTAL = Counter(
    "netscanner_ipv4_seen_total",
    "Number of intervals this ipv4 address was seen",
    [
        "address",
    ],
)
IPV6_SEEN_TOTAL = Counter(
    "netscanner_ipv6_seen_total",
    "Number of intervals this ipv6 address was seen",
    [
        "address",
    ],
)

BLACKLIST = [
    "ff:ff:ff:ff:ff:ff",
]  # list of blacklisted macs


class PacketHandler(object):
    """called if packet received"""

    def __init__(self):
        print("paket handler started")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def handle_packet(self, pkt):
        # method called if packet arrives
        # print(pkt.layers())  # show layers
        # print(pkt.summary())  # oneline summary
        # print(pkt.show())  # data structure
        # print(pkt.src)

        if pkt.dst.startswith("33:33:") or pkt.dst.startswith(
            "01:00:5e:"
        ):  # multicast ipv6 and ipv4
            return

        if (pkt.src in BLACKLIST) or (pkt.dst in BLACKLIST):  # skip if blacklisted
            return

        # prometheus metrics
        MAC_SEEN_TOTAL.labels(address=str(pkt.src)).inc()
        MAC_SEEN_TOTAL.labels(address=str(pkt.dst)).inc()

        # ipv4 update
        ip = pkt.getlayer("IP")
        if ip:
            IPV4_SEEN_TOTAL.labels(address=str(ip.src)).inc()
            IPV4_SEEN_TOTAL.labels(address=str(ip.src)).inc()
            # print(ip.summary())

        # ipv6 update
        ip6 = pkt.getlayer("ipv6")
        if ip6:
            IPV6_SEEN_TOTAL.labels(address=str(ip6.src)).inc()
            IPV6_SEEN_TOTAL.labels(address=str(ip6.dst)).inc()
            # print(ip6.summary())


def main():
    # blocking main, this should not end
    packet_handler = PacketHandler()
    logging.info("Starting scan, showing all available interfaces")
    logging.info(scapy.get_if_list())
    if EXPORTER_INTERFACE not in scapy.get_if_list():
        logging.error(f"selected interface {EXPORTER_INTERFACE} is not available")
        sys.exit(1)
    with packet_handler as ph:
        # sniff(iface=iface, prn=ph.handle_packet, filter="arp",
        # store=False)
        # sniff(iface=iface, prn=ph.handle_packet, store=False)
        if EXPORTER_INTERFACE:
            scapy.sniff(
                iface=EXPORTER_INTERFACE,
                prn=ph.handle_packet,
                store=False,
            )
        else:
            scapy.sniff(prn=ph.handle_packet, store=False)


if __name__ == "__main__":
    if EXPORTER_LOG_LEVEL == "DEBUG":
        logging.getLogger().setLevel(logging.DEBUG)
    elif EXPORTER_LOG_LEVEL == "INFO":
        logging.getLogger().setLevel(logging.INFO)
    elif EXPORTER_LOG_LEVEL == "ERROR":
        logging.getLogger().setLevel(logging.ERROR)

    logging.info(f"starting prometheus exporter on port {EXPORTER_PORT}/tcp")
    start_http_server(EXPORTER_PORT)  # start prometheus exporter on selected port

    main()  # blocking           asyncio.run(main())
