from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

# ---------------- CONFIG ----------------
MODEL = "llama3:instruct"
AI_TIMEOUT = 90
MAX_WORKERS = 1
CONTEXT_BEFORE = 3
CONTEXT_AFTER = 1

ai_cache = {}
session = requests.Session()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index3.html")

# ---------------- NORMALIZE ----------------
def normalize(line: str) -> str:
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- ROOT GROUP ----------------
def root_group_key(line: str) -> str:
    l = line.lower()

    if "service" in l and ("not running" in l or "stopped" in l or "failed" in l):
        return "SERVICE_STATE_ERROR"

    if "session" in l or "token" in l or "logon" in l:
        return "AUTH_SESSION_ERROR"

    if "process" in l or "pid" in l:
        return "PROCESS_ERROR"

    if "database" in l or "sql" in l:
        return "DATABASE_ERROR"

    if "timeout" in l or "connection" in l:
        return "NETWORK_ERROR"

    if "memory" in l or "disk" in l:
        return "RESOURCE_ERROR"

    if "registry" in l:
        return "REGISTRY_ERROR"

    if "file" in l or "read" in l or "write" in l:
        return "FILE_IO_ERROR"

    if "permission" in l or "access denied" in l:
        return "PERMISSION_ERROR"

    return normalize(line)

# ---------------- RULE FIXES ----------------
def rule_based_solution(pattern: str, sample: str):

    if pattern == "SERVICE_STATE_ERROR":
        return ("Service Error",
                "Required service is stopped or not running",
                "Restart service and check dependencies",
                "rule")

    if pattern == "FILE_IO_ERROR":
        return ("File I/O Error",
                "Application failed to read/write required file",
                "Check file path and permissions",
                "rule")

    if pattern == "AUTH_SESSION_ERROR":
        return ("Authentication Error",
                "Service cannot access active user session",
                "Run service with proper privileges",
                "rule")

    if pattern == "DATABASE_ERROR":
        return ("Database Error",
                "Database connection/query failure",
                "Check DB service and connection string",
                "rule")

    if pattern == "NETWORK_ERROR":
        return ("Network Error",
                "Connection timeout or failure",
                "Check connectivity and server",
                "rule")

    if pattern == "REGISTRY_ERROR":
        return ("Registry Error",
                "Failed to access registry key",
                "Check registry permissions",
                "rule")

    if pattern == "PERMISSION_ERROR":
        return ("Permission Error",
                "Access denied to resource",
                "Run service with required permissions",
                "rule")

    return None

# ---------------- SAFE JSON PARSER ----------------
def safe_json_extract(text):
    start = text.find("{")
    end = text.rfind("}") + 1

    if start == -1 or end == -1:
        return None

    json_text = text[start:end]

    try:
        return json.loads(json_text)
    except:
        pass

    try:
        fixed = json_text.replace("\n", " ")
        fixed = fixed.replace("'", '"')
        fixed = re.sub(r",\s*}", "}", fixed)
        return json.loads(fixed)
    except:
        return None

# ---------------- AI CALL ----------------
def ollama_analyze(sample: str, context_block: str):

    cache_key = sample + context_block
    if cache_key in ai_cache:
        return ai_cache[cache_key]

    try:
        prompt = f"""
You are a senior production support engineer.

Infer the MOST LIKELY root cause and give a PRACTICAL fix.
Be specific and technical. Never say "check logs".

Return ONLY JSON:
{{"type":"...","cause":"...","fix":"..."}}

Error:
{sample}

Context:
{context_block}
"""

        response = session.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=AI_TIMEOUT
        )

        if response.status_code != 200:
            return None

        data = response.json()
        ai_text = data.get("response", "").strip()

        parsed = safe_json_extract(ai_text)

        if not parsed:
            return None

        result = (
            parsed.get("type", "General Error"),
            parsed.get("cause", "Internal issue"),
            parsed.get("fix", ""),
            "ai"
        )

        ai_cache[cache_key] = result
        return result

    except Exception:
        return None

# ---------------- DEFAULT FIX ----------------
def default_fix(sample):
    if "service" in sample.lower():
        return "Restart service and verify dependencies"
    if "file" in sample.lower():
        return "Check file path and permissions"
    return "Investigate subsystem dependencies and configuration"

# ---------------- PROCESS ----------------
def process_pattern(pattern, occ, all_lines):
    count = len(occ)
    idx = occ[0][0]
    sample = occ[0][1]

    rule = rule_based_solution(pattern, sample)
    if rule:
        t, c, f, source = rule
    else:
        start = max(0, idx - CONTEXT_BEFORE)
        end = min(len(all_lines), idx + CONTEXT_AFTER + 1)
        context_block = "\n".join(all_lines[start:end])

        ai = ollama_analyze(sample, context_block)

        if ai:
            t, c, f, source = ai
        else:
            t = "General Error"
            c = "Likely service or configuration issue"
            f = default_fix(sample)
            source = "fallback"

        if not f:
            f = default_fix(sample)
            source = "fallback"

    return {
        "error_line": sample[:200],
        "type": t,
        "cause": c,
        "fix": f,
        "count": count,
        "source": source
    }

# ---------------- MAIN ----------------
def analyze_errors_only(log_text):
    lines = log_text.split("\n")

    error_indices = [
        (i, l) for i, l in enumerate(lines)
        if any(x in l.lower() for x in ["error", "exception", "failed", "critical"])
    ]

    total_errors = len(error_indices)
    groups = defaultdict(list)

    for idx, line in error_indices:
        key = root_group_key(line)
        groups[key].append((idx, line))

    print("Total ERROR lines:", total_errors)
    print("Root causes found:", len(groups))

    cards = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(process_pattern, pattern, occ, lines)
            for pattern, occ in groups.items()
        ]

        for f in as_completed(futures):
            cards.append(f.result())

    return {"total_errors": total_errors, "analysis": cards}

# ---------------- ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files["logfile"]
    log_text = file.read().decode("utf-8", errors="ignore")
    result = analyze_errors_only(log_text)
    return jsonify(result)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
