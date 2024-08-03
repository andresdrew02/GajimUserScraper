from scapy.all import sniff, TCP, IP
import re
import signal

users = []

def save_to_file(x,y):
    # Eliminando repetidos..
    users_list = list(set(users))
    print("[!] Guardando %i usuarios y saliendo..." % len(users_list))
    with open("users.txt", "w") as txt:
        for user in users_list:
            txt.write(user + "\n")
        exit(0)
    
signal.signal(signal.SIGINT, save_to_file)

def packet_callback(packet):
    if packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        data = bytes(tcp_layer.payload)
        if data:
            # print(f"[{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}] {data}")
            pattern = r'<value>(.*?)<'
            matches = re.findall(pattern,data.decode('utf-8'))
            for match in matches:
                if '@' not in match and ' ' not in match and not match.isnumeric():
                    users.append(match)
                    print("[i] Found %i users" % len(users))

def main():
    # Sniff TCP packets on interface tun0
    interface = "tun0"
    print(f"Sniffing TCP packets on {interface}...")
    sniff(filter="tcp", iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
