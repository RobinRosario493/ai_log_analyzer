from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

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

# ---------------- AI CALL ----------------
def ollama_analyze(sample):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3:instruct",
                "prompt": f"""
You are a senior production support engineer analyzing system logs.

Return ONLY JSON:
{{
"type": "...",
"cause": "...",
"fix": "..."
}}

Always provide a fix.

Log error:
{sample}
""",
                "stream": False
            },
            timeout=120
        )

        if response.status_code != 200:
            return "Unknown", "Bad response", "Retry request"

        data = response.json()
        ai_text = data.get("response", "").strip()

        if not ai_text:
            return "Unknown", "Empty AI output", "Check related logs"

        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1

        if start == -1 or end == -1:
            return "Unknown", ai_text, "Check logs manually"

        json_text = ai_text[start:end]

        try:
            parsed = json.loads(json_text)
        except:
            return "Unknown", ai_text, "Check logs manually"

        t = parsed.get("type", "Unknown")
        c = parsed.get("cause", "Unknown cause")
        f = parsed.get("fix", "")

        if not f or "investigation" in f.lower():
            f = "Check service dependencies, permissions, and related subsystem logs"

        return t, c, f

    except Exception as e:
        print("AI ERROR:", e)
        return "Unknown", "AI call failed", "Check Ollama server"

# ---------------- PROCESS ONE PATTERN ----------------
def process_pattern(pattern, occ):
    count = len(occ)
    sample = occ[0].lower()

    # ---------- RULE BASED ----------
    if "memory" in sample or "disk" in sample:
        t="Memory/Storage Error"
        c="System resource usage exceeded"
        f="Increase memory or free disk space"

    elif "connection" in sample or "timeout" in sample:
        t="Network Error"
        c="Network connection failure or timeout"
        f="Check network connectivity and server status"

    elif "sql" in sample or "database" in sample:
        t="Database Error"
        c="Database connection/query failure"
        f="Verify database service and connection string"

    elif "token" in sample or "logon" in sample:
        t="Authentication Error"
        c="Service unable to access active session token"
        f="Check service permissions and session context"

    elif "instance" in sample or "manager" in sample:
        t="Service Initialization Error"
        c="Required module instance not available"
        f="Check service startup order and dependencies"

    else:
        t, c, f = ollama_analyze(sample)

    return {
        "error_line": sample,
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

    for line in error_lines:
        key = normalize(line)
        groups[key].append(line)

    print("Unique patterns:", len(groups))

    cards = []

    # 🔥 PARALLEL EXECUTION
    max_workers = 3   # safe for llama3:instruct

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []

        for pattern, occ in groups.items():
            futures.append(executor.submit(process_pattern, pattern, occ))

        for future in as_completed(futures):
            try:
                result = future.result()
                cards.append(result)
            except Exception as e:
                print("THREAD ERROR:", e)

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
