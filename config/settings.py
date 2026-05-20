import os
from dotenv import load_dotenv

load_dotenv()

# AI Configuration
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# Use Groq for free testing, Claude for final submission
USE_CLAUDE = bool(ANTHROPIC_API_KEY)
MODEL_NAME = "claude-sonnet-4-20250514" if USE_CLAUDE else "llama-3.3-70b-versatile"

# Agent Configuration
MAX_ITERATIONS = 10
MAX_RETRIES = 3
CONFIDENCE_THRESHOLD = 0.75

# Case Configuration
CASES_DIR = os.path.join(os.path.dirname(__file__), "..", "cases")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports", "output")

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "nexus_ir.log"

# Guardrails (architectural - not prompt based)
FORBIDDEN_COMMANDS = ["rm", "dd", "shred", "wget", "curl", "ssh", "mkfs"]
READ_ONLY_PATHS = ["/cases/", "/mnt/", "/media/"]

print("✅ Settings loaded — AI:", MODEL_NAME)
