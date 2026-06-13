from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

# ---------------- CONFIG ----------------
MODEL = "llama3:instruct"
AI_TIMEOUT = 70
MAX_WORKERS = 1
CONTEXT_BEFORE = 3
CONTEXT_AFTER = 1
RESOLUTION_WINDOW = 50

ai_cache = {}
session = requests.Session()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("res.html")

# ---------------- NORMALIZE ----------------
def normalize(line: str) -> str:
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- ROOT GROUPING ----------------
def root_group_key(line: str) -> str:
    l = line.lower()

    if "process.start" in l or "failed to start" in l:
        return "PROCESS_LAUNCH_ERROR"

    if "service" in l and ("not running" in l or "failed" in l):
        return "SERVICE_ERROR"

    if "session" in l or "token" in l or "logon" in l:
        return "AUTH_ERROR"

    if "database" in l or "sql" in l:
        return "DATABASE_ERROR"

    if "timeout" in l or "connection" in l:
        return "NETWORK_ERROR"

    if "file" in l or "cannot find" in l or "read" in l or "write" in l:
        return "FILE_ERROR"

    if "permission" in l or "access denied" in l:
        return "PERMISSION_ERROR"

    return normalize(line)

# ---------------- RULE SOLUTIONS ----------------
def rule_based_solution(pattern: str, sample: str):

    if pattern == "PROCESS_LAUNCH_ERROR":
        return (
            "Process Launch Error",
            "Application failed to start required executable",
            "Verify executable path, permissions, and dependencies",
            "rule"
        )

    if pattern == "SERVICE_ERROR":
        return (
            "Service Error",
            "Required service failed or stopped",
            "Restart service and verify dependencies",
            "rule"
        )

    if pattern == "FILE_ERROR":
        return (
            "File I/O Error",
            "File missing or not accessible",
            "Check file path and permissions",
            "rule"
        )

    if pattern == "AUTH_ERROR":
        return (
            "Authentication Error",
            "Unable to access session or token",
            "Run service with required privileges",
            "rule"
        )

    if pattern == "DATABASE_ERROR":
        return (
            "Database Error",
            "Database connection/query failure",
            "Verify DB service and connection string",
            "rule"
        )

    if pattern == "NETWORK_ERROR":
        return (
            "Network Error",
            "Connection timeout or failure",
            "Check connectivity and server availability",
            "rule"
        )

    if pattern == "PERMISSION_ERROR":
        return (
            "Permission Error",
            "Access denied to required resource",
            "Run application with proper permissions",
            "rule"
        )

    return None

# ---------------- SAFE JSON ----------------
def safe_json_extract(text):
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end])
    except:
        try:
            fixed = text[start:end].replace("\n"," ").replace("'",'"')
            fixed = re.sub(r",\s*}", "}", fixed)
            return json.loads(fixed)
        except:
            return None

# ---------------- AI ANALYSIS ----------------
def ollama_analyze(sample, context_block):

    key = sample + context_block
    if key in ai_cache:
        return ai_cache[key]

    try:
        prompt = f"""
You are a senior production support engineer.

Infer most likely root cause and practical fix.
Return ONLY JSON.

{{"type":"...","cause":"...","fix":"..."}}

Error:
{sample}

Context:
{context_block}
"""

        r = session.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=AI_TIMEOUT
        )

        data = r.json()
        ai_text = data.get("response","")

        parsed = safe_json_extract(ai_text)
        if not parsed:
            return None

        result = (
            parsed.get("type","General Error"),
            parsed.get("cause","Internal failure"),
            parsed.get("fix",""),
            "ai"
        )

        ai_cache[key] = result
        return result

    except:
        return None

# ---------------- SUCCESS DETECTION ----------------
SUCCESS_KEYWORDS = [
    "started successfully",
    "initialized",
    "running",
    "connected",
    "ready",
    "completed",
    "recovered"
]

def is_resolved(idx, lines):
    end = min(len(lines), idx + RESOLUTION_WINDOW)
    for i in range(idx+1, end):
        l = lines[i].lower()
        for kw in SUCCESS_KEYWORDS:
            if kw in l:
                return True
    return False

# ---------------- DEFAULT FIX ----------------
def default_fix(sample):
    if "process" in sample.lower():
        return "Verify executable path and permissions"
    if "service" in sample.lower():
        return "Restart service and verify dependencies"
    if "file" in sample.lower():
        return "Check file path and permissions"
    return "Investigate configuration and dependencies"

# ---------------- PROCESS PATTERN ----------------
def process_pattern(pattern, occ, lines):

    idx = occ[0][0]
    sample = occ[0][1]
    count = len(occ)

    # resolved detection
    if is_resolved(idx, lines):
        return {
            "error_line": sample[:200],
            "count": count,
            "status": "resolved"
        }

    # rule
    rule = rule_based_solution(pattern, sample)
    if rule:
        t,c,f,source = rule
    else:
        start = max(0, idx - CONTEXT_BEFORE)
        end = min(len(lines), idx + CONTEXT_AFTER + 1)
        context_block = "\n".join(lines[start:end])

        ai = ollama_analyze(sample, context_block)

        if ai:
            t,c,f,source = ai
        else:
            t = "General Error"
            c = "Likely configuration or dependency issue"
            f = default_fix(sample)
            source = "fallback"

    return {
        "error_line": sample[:200],
        "type": t,
        "cause": c,
        "fix": f,
        "count": count,
        "source": source,
        "status": "active"
    }

# ---------------- MAIN ----------------
def analyze_errors_only(text):

    lines = text.split("\n")

    error_indices = [
        (i,l) for i,l in enumerate(lines)
        if any(x in l.lower() for x in ["error","exception","failed"])
    ]

    groups = defaultdict(list)
    for idx,line in error_indices:
        key = root_group_key(line)
        groups[key].append((idx,line))

    active=[]
    resolved=[]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures=[executor.submit(process_pattern,p,o,lines) for p,o in groups.items()]
        for f in as_completed(futures):
            r=f.result()
            if r["status"]=="resolved":
                resolved.append(r)
            else:
                active.append(r)

    return {
        "total_errors": len(error_indices),
        "active_issues": active,
        "resolved_issues": resolved
    }

# ---------------- ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files["logfile"]
    text = file.read().decode("utf-8", errors="ignore")
    return jsonify(analyze_errors_only(text))

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
