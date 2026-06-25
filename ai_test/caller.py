#!/usr/bin/env python3

import os
import sys
from openai import OpenAI
from pathlib import Path

# 测试包是否安装
try:
    from openai import OpenAI
    from  pathlib import Path 
except ImportError:
    sys.exit("缺少依赖, 先运行：pip install openai")


# api 信息
client = OpenAI(
    api_key = "xxxxx",
    base_url = "https://api.deepseek.com")

# 读取example文件
def read_file(path: str) -> str:
    # 读取文件内容，尝试常用编码
    file_path = Path(path)
    if not file_path.is_file():
        sys.exit(f"找不到文件：{path}")
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return file_path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    sys.exit(f"无法解码文件（已尝试 utf-8 / gbk / latin-1）：{path}")
    

# 消息内容
def main():
    file_text = read_file("example.txt")

    messages = [
        {"role": "system", "content": "You are a helpful os system assistant"},
        {"role": "user", "content": f"请阅读下面的文件内容并用中文回答：\n\n{file_text}"},
    ]

    response = client.chat.completions.create(
        model="deepseek-v4-pro",
        messages=messages,
        stream=False,
        reasoning_effort="high",
        extra_body={"thinking": {"type": "enabled"}}
    )

    print("\n [思考过程] \n", response.choices[0].message.reasoning_content)
    print("\n [回答] \n", response.choices[0].message.content)

if __name__ == "__main__":
    main()

