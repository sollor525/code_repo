#!/usr/bin/env python3
import hmac
import hashlib
import sys

def derive_tls_keys(client_random_hex, master_secret_hex):
    """推导TLS 1.2会话密钥"""

    try:
        client_random = bytes.fromhex(client_random_hex)
        master_secret = bytes.fromhex(master_secret_hex)

        print(f"Client Random ({len(client_random)} bytes): {client_random.hex()}")
        print(f"Master Secret ({len(master_secret)} bytes): {master_secret.hex()}")

        # TLS PRF using HMAC-SHA256
        def p_hash(secret, seed, length):
            result = b''
            a = hmac.new(secret, seed, hashlib.sha256).digest()
            result += a
            while len(result) < length:
                a = hmac.new(secret, a + seed, hashlib.sha256).digest()
                result += a
            return result[:length]

        # 生成密钥块
        seed = b"master secret" + client_random
        key_block = p_hash(master_secret, seed, 96)

        # 分割密钥块
        client_mac = key_block[0:32]
        server_mac = key_block[32:64]
        client_key = key_block[64:80]
        server_key = key_block[80:96]

        print(f"\n推导的会话密钥:")
        print(f"Client MAC: {client_mac.hex()}")
        print(f"Server MAC: {server_mac.hex()}")
        print(f"Client Key: {client_key.hex()}")
        print(f"Server Key: {server_key.hex()}")

        return {
            'client_mac': client_mac.hex(),
            'server_mac': server_mac.hex(),
            'client_key': client_key.hex(),
            'server_key': server_key.hex()
        }

    except Exception as e:
        print(f"密钥推导失败: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 derive_keys_fixed.py <client_random_hex> <master_secret_hex>")
        sys.exit(1)

    client_random_hex = sys.argv[1]
    master_secret_hex = sys.argv[2]

    keys = derive_tls_keys(client_random_hex, master_secret_hex)
    if keys:
        print("\n✅ 密钥推导成功！")
    else:
        print("\n❌ 密钥推导失败")