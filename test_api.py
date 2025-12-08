import requests
import json

# 测试 API 是否可达
def test_api_connection():
    try:
        # 首先测试根路径
        response = requests.get("http://127.0.0.1:8000/")
        print(f"根路径响应: {response.status_code}")
        print(f"响应内容: {response.text}")
        
        # 测试 /docs 路径（FastAPI 自动文档）
        response = requests.get("http://127.0.0.1:8000/docs")
        print(f"\n文档页面响应: {response.status_code}")
        
        # 列出所有可用端点
        response = requests.get("http://127.0.0.1:8000/openapi.json")
        if response.status_code == 200:
            api_spec = response.json()
            print("\n可用端点:")
            for path, methods in api_spec.get("paths", {}).items():
                print(f"  {path}: {list(methods.keys())}")
        
    except requests.exceptions.ConnectionError:
        print("错误：无法连接到 API 服务。请确保服务已启动。")
        print("运行命令：python MY_MCP\\run_mcp.py --mode api --host 127.0.0.1 --port 8000")

if __name__ == "__main__":
    test_api_connection()