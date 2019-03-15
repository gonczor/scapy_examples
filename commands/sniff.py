from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class Sniffer:
    """
    For modifying packets check nfqueue with this example:
    https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
    """
    def __init__(self, host, interface):
        super().__init__()
        self.host = host
        self.interface = interface

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type == KeyboardInterrupt:
            print('Exiting sniffer')
            return True
    
    def run(self):
        sniff(
            filter='tcp',
            lfilter=self.my_filter,
            iface=self.interface,
            prn=self.display_filtered_packet
        )

    def display_filtered_packet(self, packet: Packet):
        return packet.payload

    def my_filter(self, packet: Packet) -> bool:
        return (
                packet.getlayer(IP).src == self.host and
                packet.getlayer(TCP).sport == 80
        )


def main(host: str, interface: str):
    with Sniffer(host=host, interface=interface) as sniffer:
        sniffer.run()
