from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:instruct"

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index2.html")

# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- ROOT GROUP ----------------
def root_group_key(line):
    l = line.lower()

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

    if "service" in l:
        return "SERVICE_ERROR"

    return normalize(line)

# ---------------- DEFAULT FIX ----------------
def default_fix_for_pattern(pattern, sample):
    s = sample.lower()

    if pattern == "AUTH_SESSION_ERROR":
        return "Ensure service has permission to access active user session"

    if pattern == "PROCESS_ERROR":
        return "Verify process is running and accessible"

    if pattern == "DATABASE_ERROR":
        return "Check database service and connection string"

    if pattern == "NETWORK_ERROR":
        return "Check network connectivity and server"

    if pattern == "RESOURCE_ERROR":
        return "Check memory and disk usage"

    if pattern == "REGISTRY_ERROR":
        return "Check registry keys and permissions"

    if pattern == "SERVICE_ERROR":
        return "Restart service and verify dependencies"

    return "Check related subsystem logs and dependencies"

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
            return None

        data = response.json()
        ai_text = data.get("response","").strip()

        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1

        if start == -1:
            return None

        json_text = ai_text[start:end]

        try:
            parsed = json.loads(json_text)
        except:
            return None

        return parsed

    except Exception as e:
        print("AI ERROR:", e)
        return None

# ---------------- PROCESS PATTERN ----------------
def process_pattern(pattern, occ):
    count = len(occ)
    sample = occ[0].lower()

    # RULE BASED TYPES
    if pattern == "AUTH_SESSION_ERROR":
        t="Authentication Error"
        c="Service unable to access active session token"
        f="Check service permissions and session context"
        source="rule"

    elif pattern == "PROCESS_ERROR":
        t="Process Error"
        c="Process ID or session mapping failed"
        f="Verify running processes and permissions"
        source="rule"

    elif pattern == "DATABASE_ERROR":
        t="Database Error"
        c="Database connection/query failure"
        f="Check database service and connection"
        source="rule"

    elif pattern == "NETWORK_ERROR":
        t="Network Error"
        c="Connection or timeout failure"
        f="Check network connectivity"
        source="rule"

    elif pattern == "RESOURCE_ERROR":
        t="Resource Error"
        c="Memory or disk issue"
        f="Check system resources"
        source="rule"

    else:
        ai = ollama_analyze(sample)

        if ai:
            t = ai.get("type","General Error")
            c = ai.get("cause","Internal failure")
            f = ai.get("fix","")
            source="ai"
        else:
            t="General Error"
            c="Internal service issue"
            f=""
            source="fallback"

        if not f or f.lower() in ["", "check logs"]:
            f = default_fix_for_pattern(pattern, sample)
            source="fallback"

    return {
        "error_line": sample[:150],
        "type": t,
        "cause": c,
        "fix": f,
        "count": count,
        "source": source
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

    groups = defaultdict(list)

    for line in error_lines:
        key = root_group_key(line)
        groups[key].append(line)

    print("Total ERROR lines:", total_errors)
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
