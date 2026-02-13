#!/usr/bin/env python3
"""
TLS密钥模拟器 - 模拟发送TLS密钥数据到服务端
用于演示TLS Key Agent的完整功能
"""

import json
import socket
import time
import uuid
import secrets
import random
import argparse

class TLSKeySimulator:
    """TLS密钥模拟器"""

    def __init__(self, server_host='127.0.0.1', server_port=9999):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None

    def connect(self):
        """连接到服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(f"🔗 连接到密钥接收服务: {self.server_host}:{self.server_port}")

    def generate_random_hex(self, length):
        """生成随机十六进制字符串"""
        return secrets.token_hex(length // 2)

    def generate_tls_session(self, target_domain="example.com", target_port=443):
        """生成模拟的TLS会话数据"""
        session_id = str(uuid.uuid4())
        client_random = self.generate_random_hex(32)
        master_secret = self.generate_random_hex(48)
        session_ticket = self.generate_random_hex(64)

        # 模拟五元组
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_ip = self.get_domain_ip(target_domain)

        session_data = {
            "session_id": session_id,
            "client_random": client_random,
            "master_secret": master_secret,
            "session_ticket": session_ticket,
            "five_tuple": {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": target_port,
                "protocol": "TCP"
            },
            "timestamp": int(time.time()),
            "process_name": random.choice(["curl", "firefox", "chrome", "wget", "python"]),
            "pid": random.randint(1000, 9999)
        }

        message = {
            "message_type": "TlsKey",
            "session": session_data,
            "timestamp": int(time.time())
        }

        return message

    def get_domain_ip(self, domain):
        """获取域名的模拟IP地址"""
        # 常见域名的模拟IP
        domain_ips = {
            "baidu.com": "220.181.38.148",
            "example.com": "93.184.216.34",
            "httpbin.org": "54.230.172.55",
            "github.com": "140.82.112.3",
            "google.com": "142.250.191.14"
        }
        return domain_ips.get(domain, f"1.2.3.{random.randint(1, 254)}")

    def send_tls_key(self, message):
        """发送TLS密钥消息"""
        try:
            json_data = json.dumps(message, ensure_ascii=False)
            data_bytes = json_data.encode('utf-8')

            self.socket.sendto(data_bytes, (self.server_host, self.server_port))
            return True
        except Exception as e:
            print(f"❌ 发送失败: {e}")
            return False

    def simulate_realistic_session(self, domain="baidu.com", port=443):
        """模拟真实的TLS会话流程"""
        print(f"\n🔄 模拟与 {domain}:{port} 的TLS会话")

        # 阶段1: Client Hello (只发送Client Random)
        print("   📤 阶段1: Client Hello")
        session = self.generate_tls_session(domain, port)
        message1 = {
            "message_type": "TlsKey",
            "session": {
                "session_id": session["session_id"],
                "client_random": session["client_random"],
                "five_tuple": session["five_tuple"],
                "timestamp": session["timestamp"],
                "process_name": session["process_name"],
                "pid": session["pid"]
            },
            "timestamp": int(time.time())
        }
        self.send_tls_key(message1)
        time.sleep(0.5)

        # 阶段2: Server Hello + Key Exchange (发送Master Secret)
        print("   📥 阶段2: Server Hello + Key Exchange")
        message2 = {
            "message_type": "TlsKey",
            "session": {
                "session_id": session["session_id"],
                "client_random": session["client_random"],
                "master_secret": session["master_secret"],
                "five_tuple": session["five_tuple"],
                "timestamp": session["timestamp"] + 1,
                "process_name": session["process_name"],
                "pid": session["pid"]
            },
            "timestamp": int(time.time())
        }
        self.send_tls_key(message2)
        time.sleep(0.3)

        # 阶段3: Session Ticket (可选)
        if random.random() > 0.3:  # 70%概率有session ticket
            print("   🎫 阶段3: Session Ticket")
            message3 = {
                "message_type": "TlsKey",
                "session": {
                    "session_id": session["session_id"],
                    "client_random": session["client_random"],
                    "master_secret": session["master_secret"],
                    "session_ticket": session["session_ticket"],
                    "five_tuple": session["five_tuple"],
                    "timestamp": session["timestamp"] + 2,
                    "process_name": session["process_name"],
                    "pid": session["pid"]
                },
                "timestamp": int(time.time())
            }
            self.send_tls_key(message3)

        return session

    def close(self):
        """关闭连接"""
        if self.socket:
            self.socket.close()

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='TLS密钥模拟器')
    parser.add_argument('--host', default='127.0.0.1', help='服务器地址')
    parser.add_argument('--port', type=int, default=9999, help='服务器端口')
    parser.add_argument('--count', type=int, default=5, help='模拟会话数量')
    parser.add_argument('--delay', type=float, default=2.0, help='会话间隔(秒)')
    parser.add_argument('--realistic', action='store_true', help='模拟真实TLS握手流程')
    parser.add_argument('--domains', nargs='+',
                       default=['baidu.com', 'httpbin.org', 'github.com'],
                       help='目标域名列表')

    args = parser.parse_args()

    print("🚀 启动TLS密钥模拟器")
    print(f"🎯 目标服务器: {args.host}:{args.port}")
    print(f"📊 模拟会话数: {args.count}")
    print(f"⏱️  会话间隔: {args.delay}秒")
    print(f"🌐 目标域名: {', '.join(args.domains)}")
    print("=" * 60)

    simulator = TLSKeySimulator(args.host, args.port)

    try:
        simulator.connect()

        if args.realistic:
            # 模拟真实TLS握手流程
            for i in range(args.count):
                domain = random.choice(args.domains)
                port = 443 if domain != "example.com" else 80

                print(f"\n{'='*60}")
                print(f"🔄 模拟会话 {i+1}/{args.count}: {domain}:{port}")
                print(f"{'='*60}")

                simulator.simulate_realistic_session(domain, port)

                if i < args.count - 1:
                    print(f"⏳️  等待 {args.delay}秒...")
                    time.sleep(args.delay)
        else:
            # 简单模式 - 发送完整会话
            for i in range(args.count):
                domain = random.choice(args.domains)
                port = 443 if domain != "example.com" else 80

                print(f"\n📤 发送会话 {i+1}/{args.count}: {domain}:{port}")

                session = simulator.generate_tls_session(domain, port)
                success = simulator.send_tls_key(session)

                if success:
                    print(f"✅ 会话发送成功")
                    print(f"   Session ID: {session['session_id'][:8]}...")
                    print(f"   Client Random: {session['session']['client_random'][:16]}...")
                    print(f"   Master Secret: {session['session']['master_secret'][:16]}...")
                    print(f"   五元组: {session['session']['five_tuple']['src_ip']}:{session['session']['five_tuple']['src_port']} -> {session['session']['five_tuple']['dst_ip']}:{session['session']['five_tuple']['dst_port']}")
                else:
                    print(f"❌ 会话发送失败")

                if i < args.count - 1:
                    print(f"⏳️  等待 {args.delay}秒...")
                    time.sleep(args.delay)

        print(f"\n🎉 模拟完成! 发送了 {args.count} 个TLS会话")

    except KeyboardInterrupt:
        print(f"\n⏹️  用户中断模拟")
    except Exception as e:
        print(f"\n❌ 模拟错误: {e}")
    finally:
        simulator.close()
        print(f"👋 TLS密钥模拟器已停止")

if __name__ == '__main__':
    main()