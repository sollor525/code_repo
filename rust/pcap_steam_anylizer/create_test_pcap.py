#!/usr/bin/env python3
"""创建测试用的PCAP文件"""

from scapy.all import *
import sys

def create_test_pcap(filename="test_rst_888.pcap"):
    """创建包含SYN后RST-888和三次握手后RST-888的测试PCAP文件"""

    packets = []

    # 场景1: SYN后立即RST-ACK（窗口大小888）
    # 1. SYN
    pkt1 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
           IP(src="192.168.1.100", dst="192.168.1.200") / \
           TCP(sport=12345, dport=80, flags="S", seq=1000, window=64240)
    packets.append(pkt1)

    # 2. RST-ACK（窗口大小888）
    pkt2 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
           IP(src="192.168.1.200", dst="192.168.1.100") / \
           TCP(sport=80, dport=12345, flags="RA", seq=0, ack=1001, window=888)
    packets.append(pkt2)

    # 场景2: 三次握手后RST（窗口大小888）
    # 3. SYN
    pkt3 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
           IP(src="192.168.1.101", dst="192.168.1.201") / \
           TCP(sport=12346, dport=80, flags="S", seq=2000, window=64240)
    packets.append(pkt3)

    # 4. SYN-ACK
    pkt4 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
           IP(src="192.168.1.201", dst="192.168.1.101") / \
           TCP(sport=80, dport=12346, flags="SA", seq=3000, ack=2001, window=64240)
    packets.append(pkt4)

    # 5. ACK（完成三次握手）
    pkt5 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
           IP(src="192.168.1.101", dst="192.168.1.201") / \
           TCP(sport=12346, dport=80, flags="A", seq=2001, ack=3001, window=64240)
    packets.append(pkt5)

    # 6. RST（窗口大小888）
    pkt6 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
           IP(src="192.168.1.201", dst="192.168.1.101") / \
           TCP(sport=80, dport=12346, flags="R", seq=3001, window=888)
    packets.append(pkt6)

    # 场景3: 正常的三次握手机HTTP通信（没有RST-888）
    # 7. SYN
    pkt7 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
           IP(src="192.168.1.102", dst="192.168.1.202") / \
           TCP(sport=12347, dport=80, flags="S", seq=4000, window=64240)
    packets.append(pkt7)

    # 8. SYN-ACK
    pkt8 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
           IP(src="192.168.1.202", dst="192.168.1.102") / \
           TCP(sport=80, dport=12347, flags="SA", seq=5000, ack=4001, window=64240)
    packets.append(pkt8)

    # 9. ACK（完成三次握手）
    pkt9 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
           IP(src="192.168.1.102", dst="192.168.1.202") / \
           TCP(sport=12347, dport=80, flags="A", seq=4001, ack=5001, window=64240)
    packets.append(pkt9)

    # 10. HTTP GET
    pkt10 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
            IP(src="192.168.1.102", dst="192.168.1.202") / \
            TCP(sport=12347, dport=80, flags="PA", seq=4001, ack=5001, window=502) / \
            Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(pkt10)

    # 11. HTTP 200 OK
    pkt11 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.202", dst="192.168.1.102") / \
            TCP(sport=80, dport=12347, flags="PA", seq=5001, ack=4070, window=64240) / \
            Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
    packets.append(pkt11)

    # 12. FIN
    pkt12 = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
            IP(src="192.168.1.102", dst="192.168.1.202") / \
            TCP(sport=12347, dport=80, flags="F", seq=4070, ack=5049, window=502)
    packets.append(pkt12)

    # 13. ACK
    pkt13 = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
            IP(src="192.168.1.202", dst="192.168.1.102") / \
            TCP(sport=80, dport=12347, flags="A", seq=5049, ack=4071, window=502)
    packets.append(pkt13)

    # 写入PCAP文件
    wrpcap(filename, packets)
    print(f"Created test PCAP file: {filename}")
    print(f"Total packets: {len(packets)}")

    # 显示文件信息
    print("\nPacket summary:")
    print("1. 192.168.1.100:12345 -> 192.168.1.200:80: SYN")
    print("2. 192.168.1.200:80 -> 192.168.1.100:12345: RST-ACK (window=888)")
    print("3. 192.168.1.101:12346 -> 192.168.1.201:80: SYN")
    print("4. 192.168.1.201:80 -> 192.168.1.101:12346: SYN-ACK")
    print("5. 192.168.1.101:12346 -> 192.168.1.201:80: ACK (handshake complete)")
    print("6. 192.168.1.201:80 -> 192.168.1.101:12346: RST (window=888)")
    print("7-13. 192.168.1.102:12347 -> 192.168.1.202:80: Normal HTTP session (no RST-888)")

if __name__ == "__main__":
    create_test_pcap()