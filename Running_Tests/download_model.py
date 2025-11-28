from huggingface_hub import snapshot_download

# Hugging Face 模型名称（可改成需要的测试模型）注意需要是 instruct 版本
# model_name = "deepseek-ai/DeepSeek-Coder-1.3B-base"
model_name = "deepseek-ai/DeepSeek-Coder-1.3B-instruct"


# 指定本地下载目录
local_dir = "./deepseek-coder-1.3b"

snapshot_download(
    repo_id=model_name,
    local_dir=local_dir,
    local_dir_use_symlinks=False,   # Windows 必须设为 False

    resume_download=True,            # 支持断点续传
    allow_patterns=["*.json", "*.bin", "*.model", "*.py", "*.txt", "*.md"]
)

print("模型已下载到：", local_dir)