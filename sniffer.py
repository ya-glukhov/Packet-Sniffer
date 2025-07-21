from scapy.all import sniff, IP, TCP, UDP, DNS
import argparse
from scapy.all import wrpcap
from colorama import Fore, Style, init
init(autoreset=True)

class PacketSniffer:

    def __init__(self, interface: str, count: int = 0, filter_proto: str = "",save_path: str =""):
        self.interface = interface
        self.count = count
        self.filter_proto = filter_proto
        self.save_path = save_path
        self.captured_packets = []

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.dns_count = 0
        self.error_count = 0

    def start(self):
        sniff(
            
            iface=self.interface,
            count=self.count,
            filter=self.filter_proto if self.filter_proto != "all" else None,
            prn=self.process_packet
        )
        if self.save_path:
            wrpcap(self.save_path, self.captured_packets)
            print(f"[+] Packets saved to {self.save_path}")
        
        print(f"{Fore.MAGENTA}[=] Capture complete.")
        print(f"{Fore.WHITE}Total packets: {self.packet_count}")
        print(f"{Fore.GREEN}TCP: {self.tcp_count} {Fore.CYAN}| UDP: {self.udp_count} {Fore.YELLOW}| DNS: {self.dns_count} {Fore.RED}| Errors: {self.error_count}")

        with open("log.txt", "w") as f:
            f.write(f"[=] Capture complete.\n")
            f.write(f"Total packets: {self.packet_count}\n")
            f.write(f"TCP: {self.tcp_count}| UDP: {self.udp_count} | DNS: {self.dns_count} | Errors: {self.error_count}")


    def process_packet(self,pkt):
        print(pkt.summary())
        
        if (pkt.haslayer(IP)):
            print(f"{Fore.WHITE}[Ip]: {pkt[IP].src} → {pkt[IP].dst}")
        if pkt.haslayer(DNS):
            print("[DNS] layer found")
            if pkt[DNS].qd is not None:
                print(f"{Fore.YELLOW}[DNS]: {pkt[DNS].qd.qname.decode()}")
            else:
                print("[DNS] packet without qd")
        
        self.packet_count += 1

        try:
            if pkt.haslayer(TCP):
                self.tcp_count += 1
            elif pkt.haslayer(UDP):
                self.udp_count += 1

            if pkt.haslayer(DNS):
                self.dns_count += 1

        except Exception:
            self.error_count += 1

        if pkt.haslayer(TCP):
            print(f"{Fore.GREEN}[TCP]: {pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport}\n")
        elif pkt.haslayer(UDP):
            print(f"{Fore.CYAN}[UDP]: {pkt[IP].src}:{pkt[UDP].sport} → {pkt[IP].dst}:{pkt[UDP].dport}\n")
        self.captured_packets.append(pkt)

        
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', required=True)
    parser.add_argument('-c', '--count', type=int, default=0)
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp', 'all'], default='all')
    parser.add_argument('--save', type=str, help='Path to save captured packets (e.g. traffic.pcap)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        filter_proto=args.protocol,
        save_path=args.save
    )
    sniffer.start()
