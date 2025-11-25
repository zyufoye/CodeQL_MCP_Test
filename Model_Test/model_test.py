import json
import subprocess
import os
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

MODEL_PATH = r"C:\Users\Aono\Desktop\Project\CodeQL_MCP_Test\deepseek-coder-1.3b"

# —— 加载模型 —— #
print("加载模型中...", end="", flush=True)
tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH, 
    trust_remote_code=True
)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    device_map="auto",
    dtype=torch.float16,  # 修复：使用 dtype 而不是 torch_dtype
    trust_remote_code=True,  # 添加信任远程代码
    low_cpu_mem_usage=True  # 低内存模式
)
model.eval()
print("完成！")

def test_model_generation():
    """测试模型生成功能"""
    print("\n=== 模型生成测试 ===")
    
    # 测试用例
    test_prompts = [
        "请解释什么是SQL注入？",
        "写一个Python函数计算斐波那契数列",
        "如何修复这段代码的安全漏洞？"
    ]
    
    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n--- 测试 {i}: {prompt} ---")
        
        try:
            # 编码输入
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
            
            # 生成文本
            with torch.no_grad():  # 禁用梯度计算
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=200,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9,
                    repetition_penalty=1.1,
                    pad_token_id=tokenizer.eos_token_id
                )
            
            # 解码输出
            generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # 显示结果
            print(f"输入: {prompt}")
            print(f"生成结果: {generated_text}")
            print(f"生成长度: {len(generated_text)} 字符")
            
        except Exception as e:
            print(f"测试 {i} 失败: {e}")

def test_model_info():
    """测试模型基本信息"""
    print("\n=== 模型信息 ===")
    print(f"模型设备: {model.device}")
    print(f"模型参数量: {sum(p.numel() for p in model.parameters()):,}")
    print(f"模型类型: {type(model).__name__}")
    print(f"分词器类型: {type(tokenizer).__name__}")

def test_batch_processing():
    """测试批量处理"""
    print("\n=== 批量处理测试 ===")
    
    texts = [
        "Hello, how are you?",
        "Python is a programming language",
        "Security is important"
    ]
    
    # 批量编码
    inputs = tokenizer(texts, padding=True, truncation=True, return_tensors="pt").to(model.device)
    print(f"批量输入形状: {inputs.input_ids.shape}")
    
    # 简单的前向传播测试
    with torch.no_grad():
        outputs = model(**inputs, output_hidden_states=True)
        print(f"最后隐藏状态形状: {outputs.hidden_states[-1].shape}")

if __name__ == "__main__":
    # 运行所有测试
    test_model_info()
    test_model_generation() 
    test_batch_processing()
    
    print("\n=== 测试完成 ===")