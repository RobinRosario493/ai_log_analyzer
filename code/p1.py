from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:instruct"

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")

# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- ROOT GROUPING ----------------
def root_group_key(line):
    l = line.lower()

    # SESSION / AUTHENTICATION FAMILY
    if "session" in l or "token" in l or "logon" in l:
        return "AUTH_SESSION_ERROR"

    # PROCESS FAMILY
    if "process" in l or "pid" in l:
        return "PROCESS_ERROR"

    # DATABASE
    if "sql" in l or "database" in l:
        return "DATABASE_ERROR"

    # NETWORK
    if "timeout" in l or "connection" in l:
        return "NETWORK_ERROR"

    # MEMORY/DISK
    if "memory" in l or "disk" in l:
        return "RESOURCE_ERROR"

    # DEFAULT fallback
    return normalize(line)

# ---------------- AI CALL ----------------
def ollama_analyze(sample):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": f"""
Return ONLY JSON:
{{"type":"...","cause":"...","fix":"..."}}

Log:
{sample}
""",
                "stream": False
            },
            timeout=60
        )

        if response.status_code != 200:
            return "Unknown", "Bad response", "Retry request"

        data = response.json()
        ai_text = data.get("response", "").strip()

        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1

        if start == -1:
            return "General Error", "Auto detected", "Check logs"

        json_text = ai_text[start:end]

        try:
            parsed = json.loads(json_text)
        except:
            return "General Error", "Auto detected", "Check logs"

        t = parsed.get("type", "Unknown")
        c = parsed.get("cause", "Unknown cause")
        f = parsed.get("fix", "Check logs")

        return t, c, f

    except Exception as e:
        print("AI ERROR:", e)
        return "General Error", "AI failed", "Check logs"

# ---------------- PROCESS ----------------
def process_pattern(pattern, occ):
    count = len(occ)
    sample = occ[0].lower()

    # RULE BASED ROOT TYPES
    if pattern == "AUTH_SESSION_ERROR":
        t="Authentication Error"
        c="Service unable to access active session token"
        f="Check service permissions and session context"

    elif pattern == "PROCESS_ERROR":
        t="Process Error"
        c="Process ID or session mapping failed"
        f="Verify running processes and permissions"

    elif pattern == "DATABASE_ERROR":
        t="Database Error"
        c="Database connection/query failure"
        f="Check database service and connection"

    elif pattern == "NETWORK_ERROR":
        t="Network Error"
        c="Connection or timeout failure"
        f="Check network connectivity"

    elif pattern == "RESOURCE_ERROR":
        t="Resource Error"
        c="Memory or disk usage issue"
        f="Check system resources"

    else:
        t, c, f = ollama_analyze(sample)

    return {
        "error_line": sample[:150],
        "type": t,
        "cause": c,
        "fix": f,
        "count": count
    }

# ---------------- MAIN ----------------
def analyze_errors_only(log_text):

    lines = log_text.split("\n")

    error_lines = [
        l for l in lines
        if any(x in l.lower() for x in [
            "error","exception","failed","critical","fatal"
        ])
    ]

    total_errors = len(error_lines)

    if total_errors == 0:
        return {"total_errors":0,"analysis":[]}

    print("Total ERROR lines:", total_errors)

    groups = defaultdict(list)

    # 🔥 ROOT CAUSE GROUPING HERE
    for line in error_lines:
        key = root_group_key(line)
        groups[key].append(line)

    print("Root causes found:", len(groups))

    cards = []

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = []

        for pattern, occ in groups.items():
            futures.append(executor.submit(process_pattern, pattern, occ))

        for future in as_completed(futures):
            cards.append(future.result())

    return {
        "total_errors": total_errors,
        "analysis": cards
    }

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
