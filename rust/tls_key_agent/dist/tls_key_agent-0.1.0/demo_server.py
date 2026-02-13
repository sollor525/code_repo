#!/usr/bin/env python3
"""
TLS Key Agent 服务端演示
功能：
1. 配置管理服务 - 动态下发配置给agent
2. 密钥接收服务 - 接收并解析TLS密钥信息
3. 实时显示和统计
"""

import json
import socket
import threading
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import hashlib
import secrets

class ConfigManager:
    """配置管理器"""

    def __init__(self):
        self.configs = {}
        self.agent_configs = {}

    def get_default_config(self):
        """获取默认配置"""
        return {
            "agent": {
                "name": "tls_key_agent_demo",
                "version": "0.1.0",
                "log_level": "info",
                "buffer_pool_size": 1000,
                "buffer_size": 8192
            },
            "extraction": {
                "enabled": True,
                "kernel_version_requirement": "5.0.0",
                "capture_client_random": True,
                "capture_master_secret": True,
                "capture_session_ticket": True,
                "process_filters": ["nginx", "apache2", "httpd", "curl", "firefox", "chrome"]
            },
            "transport": {
                "enabled_transports": ["Udp"],
                "max_retries": 3,
                "timeout": 30,
                "udp": {
                    "enabled": True,
                    "server_host": "127.0.0.1",
                    "server_port": 9999,
                    "batch_size": 100,
                    "batch_timeout_ms": 1000,
                    "compression": True,
                    "reconnect_interval": 5,
                    "max_retries": 3,
                    "timeout": 30
                },
                "tcp": {
                    "enabled": False,
                    "server_host": "127.0.0.1",
                    "server_port": 9998,
                    "connection_timeout": 30,
                    "keep_alive": True,
                    "retry_delay": 1,
                    "reconnect_interval": 5,
                    "max_retries": 10,
                    "timeout": 10
                },
                "remote_config": {
                    "enabled": True,
                    "server_url": "http://127.0.0.1:8080/config",
                    "config_update_interval": 30,
                    "config_retry_attempts": 3,
                    "connection_timeout": 30
                }
            },
            "ebpf_ssl_hook": {
                "enabled": True,
                "kernel_version_requirement": "5.0.0",
                "clang_path": "/usr/bin/clang",
                "bpftool_path": "/usr/bin/bpftool",
                "auto_compile": True,
                "uprobe_timeout_ms": 3000
            },
            "injection": {
                "auto_inject": True,
                "hook_library": None,
                "process_discovery_interval": 30
            },
            "filters": [
                {
                    "name": "https_traffic",
                    "enabled": True,
                    "five_tuple": {
                        "dst_port": 443
                    },
                    "process_name": None,
                    "pid": None,
                    "source_ip_filter": None,
                    "priority": 100
                },
                {
                    "name": "http_traffic",
                    "enabled": True,
                    "five_tuple": {
                        "dst_port": 80
                    },
                    "process_name": None,
                    "pid": None,
                    "source_ip_filter": None,
                    "priority": 90
                },
                {
                    "name": "smtp_tls",
                    "enabled": True,
                    "five_tuple": {
                        "dst_port": 587,
                        "protocol": "TCP"
                    },
                    "process_name": None,
                    "pid": None,
                    "source_ip_filter": None,
                    "priority": 80
                }
            ]
        }

    def get_agent_specific_config(self, agent_id: str):
        """获取agent特定配置"""
        base_config = self.get_default_config()

        # 根据agent ID定制配置
        if "demo" in agent_id.lower():
            # Demo配置 - 更详细的日志和更小的批次
            base_config["agent"]["log_level"] = "debug"
            base_config["transport"]["udp"]["batch_size"] = 50
            base_config["transport"]["udp"]["batch_timeout_ms"] = 500

        return base_config

    def add_agent_config(self, agent_id: str, config_hash: str):
        """注册agent配置"""
        self.agent_configs[agent_id] = {
            "config_hash": config_hash,
            "last_update": time.time()
        }

class ConfigHTTPHandler(BaseHTTPRequestHandler):
    """配置HTTP请求处理器"""

    def __init__(self, *args, config_manager=None, **kwargs):
        self.config_manager = config_manager
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """处理GET请求 - 获取配置"""
        if self.path.startswith('/config'):
            self.handle_config_request()
        elif self.path.startswith('/health'):
            self.handle_health_request()
        else:
            self.send_error(404, "Not Found")

    def handle_config_request(self):
        """处理配置请求"""
        try:
            # 解析查询参数
            parsed = urlparse(self.path)
            query_params = parse_qs(parsed.query)

            agent_id = query_params.get('agent_id', ['unknown'])[0]
            config_hash = query_params.get('config_hash', [''])[0]

            # 获取配置
            config = self.config_manager.get_agent_specific_config(agent_id)

            # 计算配置哈希
            config_str = json.dumps(config, sort_keys=True)
            current_hash = hashlib.md5(config_str.encode()).hexdigest()

            # 检查是否需要更新
            if config_hash and config_hash == current_hash:
                response = {
                    "status": "no_update",
                    "message": "Configuration is up to date",
                    "current_hash": current_hash
                }
            else:
                # 注册agent
                self.config_manager.add_agent_config(agent_id, current_hash)

                response = {
                    "status": "updated",
                    "message": "Configuration updated",
                    "config": config,
                    "config_hash": current_hash,
                    "update_interval": 30
                }

            # 发送响应
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response_json = json.dumps(response, indent=2, ensure_ascii=False)
            self.wfile.write(response_json.encode('utf-8'))

            print(f"📋 配置请求: Agent={agent_id}, Hash={config_hash[:8]}..., 状态={response['status']}")

        except Exception as e:
            print(f"❌ 配置请求错误: {e}")
            self.send_error(500, str(e))

    def handle_health_request(self):
        """处理健康检查请求"""
        response = {
            "status": "healthy",
            "timestamp": time.time(),
            "registered_agents": len(self.config_manager.agent_configs)
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        response_json = json.dumps(response, indent=2)
        self.wfile.write(response_json.encode('utf-8'))

    def log_message(self, format, *args):
        """重写日志方法以减少输出"""
        pass

class KeyReceiver:
    """TLS密钥接收器"""

    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.stats = {
            'total_keys': 0,
            'client_random_count': 0,
            'master_secret_count': 0,
            'unique_sessions': set(),
            'start_time': time.time()
        }

    def start(self):
        """启动密钥接收服务"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        print(f"🔐 TLS密钥接收服务启动: {self.host}:{self.port}")
        print(f"📊 等待TLS密钥数据...")

        try:
            while True:
                data, addr = self.socket.recvfrom(65535)
                self.process_key_data(data, addr)
        except KeyboardInterrupt:
            print(f"\n⏹️  停止密钥接收服务")
        finally:
            if self.socket:
                self.socket.close()

    def process_key_data(self, data, addr):
        """处理密钥数据"""
        try:
            # 解析JSON消息
            message = json.loads(data.decode('utf-8'))

            # 更新统计
            self.stats['total_keys'] += 1

            if message.get('message_type') == 'TlsKey':
                session = message.get('session', {})

                # 提取会话信息
                session_id = session.get('session_id', 'unknown')
                self.stats['unique_sessions'].add(session_id)

                # 显示密钥信息
                self.display_key_info(session, addr)

                # 更新统计
                if 'client_random' in session:
                    self.stats['client_random_count'] += 1
                if 'master_secret' in session:
                    self.stats['master_secret_count'] += 1

        except json.JSONDecodeError as e:
            print(f"❌ JSON解析错误: {e}")
        except Exception as e:
            print(f"❌ 处理密钥数据错误: {e}")

    def display_key_info(self, session, addr):
        """显示密钥信息"""
        print(f"\n{'='*60}")
        print(f"🔐 收到TLS密钥信息 (来源: {addr[0]}:{addr[1]})")
        print(f"⏰ 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # 会话基本信息
        session_id = session.get('session_id', 'N/A')
        process_name = session.get('process_name', 'N/A')
        pid = session.get('pid', 'N/A')

        print(f"📋 会话ID: {session_id}")
        print(f"🔧 进程: {process_name} (PID: {pid})")

        # 五元组信息
        five_tuple = session.get('five_tuple', {})
        if five_tuple:
            print(f"🌐 网络信息:")
            print(f"   源地址: {five_tuple.get('src_ip', 'N/A')}:{five_tuple.get('src_port', 'N/A')}")
            print(f"   目标地址: {five_tuple.get('dst_ip', 'N/A')}:{five_tuple.get('dst_port', 'N/A')}")
            print(f"   协议: {five_tuple.get('protocol', 'N/A')}")

        # 密钥信息
        print(f"🔑 TLS密钥:")

        if 'client_random' in session:
            client_random = session['client_random']
            print(f"   Client Random: {client_random}")
            print(f"   长度: {len(client_random)} 字符")

        if 'master_secret' in session:
            master_secret = session['master_secret']
            print(f"   Master Secret: {master_secret}")
            print(f"   长度: {len(master_secret)} 字符")

        # 其他信息
        if 'session_ticket' in session:
            session_ticket = session['session_ticket']
            print(f"   Session Ticket: {session_ticket}")
            print(f"   长度: {len(session_ticket)} 字符")

        print(f"{'='*60}")

        # 显示统计信息
        self.show_stats()

    def show_stats(self):
        """显示统计信息"""
        runtime = time.time() - self.stats['start_time']

        print(f"\n📊 实时统计:")
        print(f"   运行时间: {runtime:.1f}秒")
        print(f"   总密钥数: {self.stats['total_keys']}")
        print(f"   Client Random: {self.stats['client_random_count']}")
        print(f"   Master Secret: {self.stats['master_secret_count']}")
        print(f"   唯一会话数: {len(self.stats['unique_sessions'])}")
        print(f"   平均速率: {self.stats['total_keys']/runtime:.2f} 密钥/秒")

class TLSDemoServer:
    """TLS Demo 服务器"""

    def __init__(self, config_port=8080, key_port=9999):
        self.config_manager = ConfigManager()
        self.config_port = config_port
        self.key_port = key_port
        self.config_server = None
        self.key_receiver = None

    def start(self):
        """启动服务"""
        print(f"🚀 启动TLS Key Agent Demo服务器")
        print(f"📋 配置服务端口: {self.config_port}")
        print(f"🔐 密钥接收端口: {self.key_port}")
        print(f"⏰ 启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")

        # 启动配置服务
        self.start_config_service()

        # 启动密钥接收服务
        self.start_key_service()

    def start_config_service(self):
        """启动配置服务"""
        def handler_factory(*args, **kwargs):
            return ConfigHTTPHandler(*args, config_manager=self.config_manager, **kwargs)

        self.config_server = HTTPServer(('127.0.0.1', self.config_port), handler_factory)

        # 在单独线程中运行配置服务
        config_thread = threading.Thread(target=self.config_server.serve_forever, daemon=True)
        config_thread.start()

        print(f"📋 配置服务已启动: http://127.0.0.1:{self.config_port}")
        print(f"   - 配置端点: http://127.0.0.1:{self.config_port}/config?agent_id=demo")
        print(f"   - 健康检查: http://127.0.0.1:{self.config_port}/health")

    def start_key_service(self):
        """启动密钥接收服务"""
        self.key_receiver = KeyReceiver(port=self.key_port)

        # 在主线程中运行密钥接收服务
        self.key_receiver.start()

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='TLS Key Agent Demo服务器')
    parser.add_argument('--config-port', type=int, default=8080, help='配置服务端口')
    parser.add_argument('--key-port', type=int, default=9999, help='密钥接收端口')
    parser.add_argument('--demo-config', action='store_true', help='显示demo配置')

    args = parser.parse_args()

    if args.demo_config:
        # 显示demo配置
        config_manager = ConfigManager()
        config = config_manager.get_default_config()
        print("📋 Demo配置:")
        print(json.dumps(config, indent=2, ensure_ascii=False))
        return

    # 启动服务器
    server = TLSDemoServer(args.config_port, args.key_port)

    try:
        server.start()
    except KeyboardInterrupt:
        print(f"\n👋 服务器已停止")
    except Exception as e:
        print(f"❌ 服务器错误: {e}")

if __name__ == '__main__':
    main()