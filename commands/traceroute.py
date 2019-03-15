from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def main(host: str, *_):
    for ttl in range(1, 16):
        packet = IP(dst=host, ttl=ttl)/ICMP()
        response = sr1(packet, verbose=0)
        if response is None:
            print('Did not receive any response. Quitting')
            return
        elif response.src == host:
            print(f'{ttl}\t{response.src}\tdestination reached.')
            return
        else:
            print(f'{ttl}\t{response.src}')
    print('TTL over 255. Quitting.')
