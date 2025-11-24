import sqlite3

def login_user(username, password):
    """
    用户登录函数 - 包含SQL注入漏洞 - 测试
    """
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 有漏洞的SQL查询 - 直接拼接用户输入
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    print(f"执行的SQL: {query}")
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        print("登录成功!")
        return True
    else:
        print("登录失败!")
        return False

def search_products(keyword):
    """
    产品搜索函数 - 包含SQL注入漏洞
    """
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 有漏洞的SQL查询
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    
    print(f"执行的SQL: {query}")
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    
    return results

def get_user_by_id(user_id):
    """
    根据用户ID获取用户信息 - 包含SQL注入漏洞
    """
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 有漏洞的SQL查询
    query = "SELECT * FROM users WHERE id = " + user_id
    
    print(f"执行的SQL: {query}")
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    
    return result

# 测试示例
if __name__ == "__main__":
    # 正常输入测试
    print("=== 正常输入测试 ===")
    login_user("admin", "password123")
    
    print("\n=== SQL注入攻击测试 ===")
    # SQL注入攻击示例
    # 绕过密码检查
    login_user("admin' --", "anything")
    
    # 获取所有用户
    login_user("' OR '1'='1' --", "anything")
    
    # 联合查询获取敏感数据
    login_user("' UNION SELECT * FROM users --", "anything")