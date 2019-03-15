from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1


def main(host: str, *_):
    conf.verb = 0
    for port in range(1, 1001):
        response = sr1(IP(dst=host)/TCP(dport=port, flags='S'), verbose=0)
        if response.getlayer(TCP).flags == 'SA':
            print(f'{port}: OPEN')
