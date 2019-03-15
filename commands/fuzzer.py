from scapy.layers.inet import IP, TCP
from scapy.packet import fuzz
from scapy.sendrecv import sr1


def main(host: str, port: int):
    while True:
        packet = fuzz(IP(dst=host)/TCP(dport=port))
        print(f'Fuzzing packet to {packet.getlayer(IP).dst}:{packet.getlayer(TCP).dport}')
        response = sr1(packet, verbose=0, timeout=1)
        if response is not None:
            print(f'response payload: {response.payload}')
        else:
            print(f'Request flags: {packet.getlayer(TCP).flags}')
