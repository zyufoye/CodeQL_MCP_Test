from check.path_check import is_valid_path # 路径检查
from check.project_analyze import * # 项目自动分析
from config import *

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
            # 根据项目路径，分析项目 
            result = auto_analyze_project(user_input)
            print(f"\n系统：{result}")
            continue

        # 构造 Prompt
        prompt = f"""你是代码安全专家，能理解用户需求并给出专业回答。
用户请求：{user_input}

请根据用户输入的内容，提供相关的安全分析或建议：
- 如果用户提供了项目路径，询问是否需要分析
- 如果用户询问安全问题，给出专业回答
- 如果输入不明确，询问更多细节

请用简洁专业的语言回复。
"""

        print(f"[Prompt] 向模型提问 : {prompt}")
        # 模型推理
        inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
        out = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=True,
            temperature=0.8,
            top_p=0.9,
            top_k=50,
            repetition_penalty=1.1,
            pad_token_id=tokenizer.eos_token_id,
        )

        text = tokenizer.decode(out[0], skip_special_tokens=True)

        # 提取模型回复内容
        # 提取实际回复内容，去除提示词部分
        lines = text.split('\n')
        response_start = False
        response = []
        
        for line in lines:
            if "用户请求" in line:
                response_start = True
                continue
            if response_start and not (line.startswith("如果") or "回复：" in line or not line.strip()):
                response.append(line)
        
        # 如果没能正确提取，使用简单的回退方法
        if not response:
            parts = text.split("用户请求：")
            if len(parts) > 1:
                parts = parts[1].split("如果用户")
                response = [parts[0].strip()]
        
        # 输出处理后的回复
        final_response = "\n".join(response).strip()
        # 避免重复用户请求的情况
        if user_input in final_response:
            final_response = final_response.replace(user_input, "").strip()
        
        print(f"\n [* System Final Response] {final_response}")


if __name__ == "__main__":
    chat_loop()
    print("\n分析会话结束。")
