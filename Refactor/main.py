from check.path_check import is_valid_path # 路径检查
from check.project_analyze import auto_analyze_project # 项目自动分析


# 主聊天循环

def chat_loop():
    print("\n=== MCP 安全分析系统 (输入 quit 或 exit 结束) ===")
    print("提示: 你可以直接输入项目路径进行自动分析，或者询问安全相关问题")
    while True:
        user_input = input("\n 请输入项目路径（目录）：").strip()
        if user_input.lower() in ("quit", "exit"): 
            break
            
        # 检查是否是路径
        if is_valid_path(user_input):
            # 直接分析项目 ,卡在了这里
            result = auto_analyze_project(user_input)
            print(f"\n系统：{result}")
            continue



if __name__ == "__main__":
    chat_loop()
    print("\n分析会话结束。")
