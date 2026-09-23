"""Vuln Management - core utilities"""

import os
import re
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

from .models.db import DB_PATH, init_db  # noqa: E402

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.MiniMax.chat/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "MiniMax-M3")


def strip_thinking(content: str) -> str:
    content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL)
    content = re.sub(r"<think>.*$", "", content, flags=re.DOTALL)
    for m in [r"^OK final structure:.*$", r"^OK let me.*$", r"^Actually.*$"]:
        if match := re.search(m, content, flags=re.MULTILINE):
            content = content[:match.start()].rstrip() + "\n"
            break
    return content.strip() + "\n"


def call_llm(system_prompt, user_prompt):
    api_key = LLM_API_KEY or os.environ.get("LLM_API_KEY", "")
    if not api_key:
        raise ValueError("LLM_API_KEY 未配置")
    url = LLM_BASE_URL.rstrip("/") + "/chat/completions"
    headers = {"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
    payload = {
        "model": LLM_MODEL,
        "temperature": 0.3,
        "max_tokens": 4000,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=300)
    resp.raise_for_status()
    return strip_thinking(resp.json()["choices"][0]["message"]["content"])


def load_prompt(name):
    path = ROOT / "prompts" / name
    if not path.exists():
        raise FileNotFoundError("Prompt not found: " + str(path))
    return path.read_text(encoding="utf-8")


__all__ = [
    "ROOT", "DATA_DIR", "DB_PATH", "init_db",
    "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL",
    "strip_thinking", "call_llm", "load_prompt",
]
