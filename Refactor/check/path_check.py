import os
import re


def normalize_path(path): # 1
    """标准化路径，处理引号和反斜杠"""
    # 移除引号
    path = path.strip('"\'')
    # 确保路径分隔符正确
    return os.path.normpath(path)

# print(normalize_path("C:\\Users\\Aono\\Desktop\\Project\\CodeQL_MCP_Test\\Refactor"))
# file_path = r"C:\Users\Aono\Desktop\Project\CodeQL_MCP_Test\Target_Test\test.c"
# print(normalize_path(file_path))

def is_valid_path(path):  # 2
    """检查路径是否有效"""
    try:
        path = normalize_path(path)
        # 检查路径是否存在
        if os.path.exists(path):
            return True
        # 检查是否是有效的Windows路径格式
        # - ^ - 匹配字符串开头
        # - [a-zA-Z] - 匹配一个字母（A-Z或a-z）
        # - : - 匹配冒号
        # - \\ - 匹配反斜杠（由于在原始字符串中，单个 \ 需要转义）
        if re.match(r'^[a-zA-Z]:\\', path):
            return True
        # 检查是否是有效的Unix路径格式
        if path.startswith('/'):
            return True
        return False
    except:
        return False

