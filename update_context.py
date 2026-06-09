"""
OVP — update_context.py

Run this from your project root after completing any phase.
It reads your core data models and writes CONTEXT.md automatically.

Usage:
    python update_context.py
"""

import os
import sys
from datetime import datetime

# Files to embed in CONTEXT.md
CORE_FILES = [
    "core/finding.py",
    "core/verdict.py",
    "core/evidence.py",
]

# Update this manually when you move to a new phase
CURRENT_PHASE = "Phase 2 — Core Engine + Rule Judge"

FOLDER_STRUCTURE = """
ovp/
├── vulnerable_lab/
│   ├── chatbot1/          (port 8000 vulnerable, 8001 hardened)
│   ├── chatbot2/          (coming Phase 3)
│   └── chatbot3/          (coming Phase 3 — RAG)
├── core/                  (data models + engine)
├── judges/                (rule_judge, llm_judge)
├── attacks/               (one file per attack class)
├── reports/
├── analytics/
└── tests/
""".strip()

AGENT_RULES = """
- Never change existing dataclass field names or types
- Never change enum values
- Always import models from core/ — never redefine them locally
- Always load API key via config.py — never hardcode
- Never combine two tasks into one session
- Always use async/await for target communication
- Use rich for all terminal output
""".strip()


def read_file(path: str) -> str:
    if not os.path.exists(path):
        return f"# FILE NOT FOUND: {path}\n# Run this script again after creating it.\n"
    # Added encoding="utf-8" to handle unicode characters in embedded files safely
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def build_context() -> str:
    sections = []

    # Header
    sections.append(f"""# OVP — Project Context
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

Paste this entire file at the start of every coding agent session.
The agent must read and follow everything here before writing any code.

---

## Project
**Name:** OVP — AI Exploitability Validation Platform
**Purpose:** Takes an AI security finding → generates attack payloads →
fires them against a target → evaluates results → returns a verdict
with evidence proving whether the finding is actually exploitable.

---

## Current Phase
{CURRENT_PHASE}

---

## Stack
- Python 3.11+
- FastAPI (vulnerable lab targets)
- httpx (async HTTP client)
- SQLite (analytics)
- pytest + pytest-asyncio (tests)
- rich (terminal output)

---

## Folder Structure
{FOLDER_STRUCTURE}


---

## Rules for the Coding Agent
{AGENT_RULES}

---

## Data Models (DO NOT MODIFY THESE SCHEMAS)
""")

    # Embed each core file
    for filepath in CORE_FILES:
        filename = os.path.basename(filepath)
        content = read_file(filepath)
        sections.append(f"### {filepath}\n```python\n{content}\n```\n")

    # Footer
    sections.append("""---

## How to Use This File
1. Copy everything above this line
2. Paste it as the FIRST message in your coding agent session
3. Then describe the task you want done
4. The agent now has full context and will not deviate from your schemas

## Session Template
[paste full CONTEXT.md here]

Current task:
[describe what to build]

Do not modify any existing schemas.
Do not create new files outside the established structure.

""")

    return "\n".join(sections)


def main():
    # Make sure we're in the project root
    missing = [f for f in CORE_FILES if not os.path.exists(f)]

    if missing:
        print(f"⚠️  Warning: these files don't exist yet and will be placeholders:")
        for f in missing:
            print(f"    - {f}")
        print()

    context = build_context()

    # Added encoding="utf-8" to fix Windows cp1252 crash on arrows/emojis
    with open("CONTEXT.md", "w", encoding="utf-8") as f:
        f.write(context)

    size = len(context)
    print(f"✅  CONTEXT.md written ({size:,} chars)")
    print(f"📋  Current phase: {CURRENT_PHASE}")
    print(f"📁  Embedded {len(CORE_FILES)} core files")
    print()
    print("Next step: paste CONTEXT.md at the start of your next agent session.")


if __name__ == "__main__":
    # Must be run from project root
    if not os.path.exists("core") and not os.path.exists("vulnerable_lab"):
        print("❌  Run this from your OVP project root directory.")
        print(f"    Current directory: {os.getcwd()}")
        sys.exit(1)

    main()