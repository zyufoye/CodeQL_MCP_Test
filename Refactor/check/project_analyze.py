import os
from check.path_check import normalize_path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import *
from CodeQL.query_scanner import collect_all_queries
from CodeQL.codeql_wapper import *
import re
from collections import Counter


def get_file_info(file_path):
    """获取文件的基本信息"""
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        lines = content.count('\n') + 1
        return {
            "path": file_path,
            "size": file_size,
            "lines": lines,
            "content": content
        }
    except Exception as e:
        return {
            "path": file_path,
            "size": 0,
            "lines": 0,
            "error": str(e)
        }

def scan_project(project_path, max_files=100, file_extensions=None): # 5
    """扫描项目结构，提取关键信息"""
    if not os.path.exists(project_path):
        return {"error": f"项目路径 {project_path} 不存在"}
    
    if file_extensions is None:
        file_extensions = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', '.go', '.rb', '.php']
    
    # 默认忽略的目录
    ignore_dirs = ['.git', '.svn', 'node_modules', 'venv', 'env', '__pycache__', 'bin', 'obj', 'build', 'dist']
    
    project_info = {
        "path": project_path,
        "name": os.path.basename(project_path),
        "files": [],
        "file_types": {},
        "total_files": 0,
        "total_size": 0,
        "total_lines": 0,
        "available_queries": None
    }
    
    file_counter = 0
    for root, dirs, files in os.walk(project_path):
        # 跳过忽略的目录
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            
            # 只处理指定的文件类型
            if ext not in file_extensions:
                continue
            
            # 文件类型统计
            project_info["file_types"][ext] = project_info["file_types"].get(ext, 0) + 1
            project_info["total_files"] += 1
            
            # 限制处理的文件数量
            if file_counter < max_files:
                file_info = get_file_info(file_path)
                project_info["files"].append(file_info)
                project_info["total_size"] += file_info.get("size", 0)
                project_info["total_lines"] += file_info.get("lines", 0)
                file_counter += 1
    
    # 自动扫描所有可用 QL/QLS 查询
    codeql_root = CODEQL_ROOT_QUERY

    if os.path.exists(codeql_root):
        project_info['available_queries'] = collect_all_queries(codeql_root)
    else:
        project_info['available_queries'] = {}
    
    return project_info

def extract_imports(project_info): # 6
    """提取项目中的导入语句"""
    imports = {
        "python": [],
        "javascript": [],
        "java": [],
        "csharp": [],
        "cpp": []
    }
    
    for file in project_info["files"]:
        if "content" not in file:
            continue
            
        ext = os.path.splitext(file["path"])[1].lower()
        content = file["content"]
        
        # Python导入
        if ext == '.py':
            py_imports = re.findall(r'^\s*(?:import|from)\s+([^\s]+)', content, re.MULTILINE)
            imports["python"].extend(py_imports)
        
        # JavaScript/TypeScript导入
        elif ext in ['.js', '.ts']:
            js_imports = re.findall(r'(?:import|require)\s*\(?[\'"]([^\'"]+)[\'"]', content)
            imports["javascript"].extend(js_imports)
        
        # Java导入
        elif ext == '.java':
            java_imports = re.findall(r'import\s+([^;]+);', content)
            imports["java"].extend(java_imports)
        
        # C#导入
        elif ext == '.cs':
            cs_imports = re.findall(r'using\s+([^;]+);', content)
            imports["csharp"].extend(cs_imports)
        
        # C/C++导入
        elif ext in ['.c', '.cpp', '.h', '.hpp']:
            cpp_imports = re.findall(r'#include\s*[<"]([^>"]+)[>"]', content)
            imports["cpp"].extend(cpp_imports)
    
    # 统计导入频率
    for lang in imports:
        counter = Counter(imports[lang])
        imports[lang] = [{"name": name, "count": count} for name, count in counter.most_common()]
    
    return imports


def analyze_project(project_path, max_files=100): # 4
    """分析项目并生成摘要信息"""
    project_info = scan_project(project_path, max_files)
    
    if "error" in project_info:
        return project_info
    
    # 提取导入信息
    imports = extract_imports(project_info)
    
    # 移除文件内容以减小结果大小
    for file in project_info["files"]:
        if "content" in file:
            del file["content"]
    
    # 项目摘要
    summary = {
        "project_name": project_info["name"],
        "project_path": project_info["path"],
        "total_files": project_info["total_files"],
        "total_size": project_info["total_size"],
        "total_lines": project_info["total_lines"],
        "file_types": project_info["file_types"],
        "imports": imports,
        "available_queries": project_info["available_queries"]
    }

    print(f"项目摘要信息: {summary}")
    
    return summary

def choose_query_file(user_input, available_queries, language):
    lang_queries = available_queries.get(language, {})
    
    # 优先 security-and-quality
    for q in lang_queries.get("qls", []):
        if "security-and-quality" in q:
            return q, "优先选择官方安全与质量套件"
    # 其次 security
    for q in lang_queries.get("qls", []):
        if "security" in q:
            return q, "优先选择安全相关套件"
    # 专项需求
    if "cve" in user_input.lower():
        for q in lang_queries.get("ql", []):
            if "cve" in q.lower():
                return q, "根据用户需求，选择CVE专项规则"
    if "sql注入" in user_input.lower() or "sql injection" in user_input.lower():
        for q in lang_queries.get("ql", []):
            if "sqlinjection" in q.lower() or "sql_injection" in q.lower():
                return q, "根据用户需求，选择SQL注入专项规则"
    # 兜底
    if lang_queries.get("qls"):
        return lang_queries["qls"][0], "默认选择第一个套件"
    if lang_queries.get("ql"):
        return lang_queries["ql"][0], "默认选择第一个规则"
    return None, "未找到合适的查询文件"


def summarize_sarif(sarif_path):
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            if "locations" in r and r["locations"]:
                loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                line = r["locations"][0]["physicalLocation"].get("region", {}).get("startLine", "?")
                msg = r["message"]["text"]
                rule_id = r.get("ruleId", "未知规则")
                severity = r.get("properties", {}).get("severity", "警告")
                findings.append({
                    "file": loc,
                    "line": line,
                    "rule": rule_id,
                    "severity": severity,
                    "desc": msg
                })
    return findings

def generate_natural_report(findings, project_info, user_input):
    prompt = f"""你是一名资深代码安全专家。请根据以下项目分析结果，生成一份专业、自然、面向开发者的安全分析报告。
项目名称：{project_info['project_name']}
主要语言：{project_info['file_types']}
用户需求：{user_input}
本次自动化分析共发现 {len(findings)} 个安全相关问题，关键信息如下（仅供参考）：
{json.dumps(findings[:10], ensure_ascii=False, indent=2)}

请用真实安全专家的口吻，像写正式安全评估报告一样，综合分析本次结果，指出主要风险、典型漏洞、整改建议等。风格可以灵活，不要机械分点，适当穿插解释和建议。不要直接输出原始数据。
"""
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
    out = model.generate(**inputs, max_new_tokens=768)
    text = tokenizer.decode(out[0], skip_special_tokens=True)
    return text


def auto_analyze_project(path): # 3
    """自动分析项目并返回自然语言安全报告"""
    # 标准化路径
    path = normalize_path(path)
    if not os.path.exists(path):
        return f"错误：路径 '{path}' 不存在或无法访问"
    print(f"正在分析项目: {path}...")
    
    # 1. 项目结构分析
    project_info = analyze_project(path)
    if "error" in project_info:
        return f"分析错误: {project_info['error']}"
    
    # 2. 检测语言并执行CodeQL分析
    language = detect_language(path)
    if not language:
        return f"项目分析完成，但无法检测主要编程语言\n\n项目名称: {project_info['project_name']}\n文件总数: {project_info['total_files']}\n代码行数: {project_info['total_lines']}"
    


    # 3. 自动选择 QLS 套件或 QL 单条规则
    query_path, reason = choose_query_file(path, project_info.get("available_queries", {}), language)
    if query_path and not os.path.isabs(query_path):
        query_path = os.path.abspath(os.path.join(CODEQL_ROOT_QUERY, query_path))
    if query_path:
        query_path = query_path.replace("\\", "/")

    print(f"[query_path] 选择的查询文件: {query_path} ({reason})")

    output_path = os.path.join(OUTPUT_DIR, f"codeql_results_{os.path.basename(path)}.sarif")
    codeql_results = call_codeql(path, query_path=query_path, output_path=output_path, language=language)

    # 4. 检查 SARIF 文件是否存在
    if not os.path.exists(output_path):
        return f"CodeQL 分析失败，未生成结果文件。请检查数据库创建和分析阶段是否有报错。\n详细信息：{codeql_results}"
    
    findings = summarize_sarif(output_path)
    
    # 5. 只传递结构化信息和风格指令给大模型，由大模型自由生成报告
    return generate_natural_report(findings, project_info, path)

