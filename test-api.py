import requests
import json

def test_deepseek(api_key):
    # 1. 测试标准接口
    print("正在测试标准接口...")
    standard_url = "https://api.deepseek.com/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": "Ping"}]
    }
    
    try:
        res = requests.post(standard_url, headers=headers, json=payload)
        print(f"状态码: {res.status_code}")
        print(f"响应内容: {res.text}\n")
    except Exception as e:
        print(f"标准接口连接失败: {e}\n")

    # 2. 测试兼容接口 (针对 Claude Code)
    print("正在测试 Anthropic 兼容接口...")
    compat_url = "https://api.deepseek.com/anthropic/v1/messages"
    compat_headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"
    }
    compat_payload = {
        "model": "deepseek-v4-pro",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "Hi"}]
    }
    
    try:
        res = requests.post(compat_url, headers=compat_headers, json=compat_payload)
        print(f"状态码: {res.status_code}")
        print(f"响应内容: {res.text}")
    except Exception as e:
        print(f"兼容接口连接失败: {e}")

if __name__ == "__main__":
    my_key = "sk-bfbc9197e9064de1ae975ccf59bc9a64"
    test_deepseek(my_key)
    