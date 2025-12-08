import requests
import json

# 确保服务已启动
print("测试 MCP API 连接...")

# 方法1：使用 mcp_api.py 中的端点（如果存在）
try:
    response = requests.post(
        "http://127.0.0.1:8000/analyze_sync",
        json={"project_path": "requirements.txt"}
    )
    print(f"方法1响应: {response.status_code}")
    print(f"响应内容: {response.json()}")
except Exception as e:
    print(f"方法1失败: {e}")

# # 方法2：检查 cli_chat.py 中的端点
# try:
#     response = requests.post(
#         "http://127.0.0.1:8000/analyze_sync",
#         json={"project_path": "D:\\Projects\\CodeQL_MCP_Demo\\Really_MCP\\Test"}
#     )
#     print(f"\n方法2响应: {response.status_code}")
#     print(f"响应内容: {response.json()}")
# except Exception as e:
#     print(f"方法2失败: {e}")

# # 方法3：直接调用 auto_analyze_project 函数
# print("\n方法3：直接调用函数...")
# import sys
# sys.path.append("MY_MCP")
# from cli_chat import auto_analyze_project

# result = auto_analyze_project("D:\\Projects\\CodeQL_MCP_Demo\\Really_MCP\\Test")
# print(f"直接调用结果: {result[:200]}...")  # 只显示前200个字符