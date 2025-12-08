import requests
import json

# 同步分析
response = requests.post(
    "http://localhost:8000/analyze_sync",
    json={"project_path": "D:\\Projects\\CodeQL_MCP_Demo\\Really_MCP\\Test"}
)
print(response.json())
