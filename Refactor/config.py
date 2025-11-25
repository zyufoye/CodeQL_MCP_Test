import os
import torch

CODEQL_ROOT_QUERY = r"C:\Users\Aono\Desktop\Project\codeql-win64\codeql\codeql-main"

# CodeQL路径配置
CODEQL_PATH = r"C:\Users\Aono\Desktop\Project\codeql-win64\codeql"
CODEQL_BIN = os.path.join(CODEQL_PATH, "codeql.exe")
CODEQL_QUERIES = r"C:\Users\Aono\Desktop\Project\codeql-win64\codeql\codeql-main"

OUTPUT_DIR = r"C:\Users\Aono\Desktop\Project\CodeQL_MCP_Test\results\Test"

DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

MODEL_PATH = r"C:\Users\Aono\Desktop\Project\CodeQL_MCP_Test\deepseek-coder-1.3b"