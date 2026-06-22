#!/usr/bin/env python3

import os
import sys
from openai import OpenAI

# config 


client = OpenAI(
    api_key = "xxxxxx",
    base_url = "https://api.deepseek.com")


message = []
message.append({"role": "system", "content": "You are a helpful os system assistant"})
message.append({"role": "user", "content": "Hello,what model are you? please use chinses to answer me! "})

response = client.chat.completions.create(
    model="deepseek-v4-pro",
    messages=message,
    stream=False,
    reasoning_effort="high",
    extra_body={"thinking": {"type": "enabled"}}
)

print(response.choices[0].message.content)
