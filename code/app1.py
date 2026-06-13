from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import re
from collections import defaultdict

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
                "model": "llama3:instruct",   # 🔥 better model
                "prompt": f"""
You are a senior production support engineer analyzing system logs.

Your job:
1. Classify the error type
2. Infer the most likely technical cause
3. Suggest a practical fix

You MUST always provide a fix.
Never say "investigation required".

Return ONLY JSON:
{{
"type": "...",
"cause": "...",
"fix": "..."
}}

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
            return "Unknown", ai_text, "Check service logs"

        json_text = ai_text[start:end]

        try:
            parsed = json.loads(json_text)
        except:
            return "Unknown", ai_text, "Check logs manually"

        t = parsed.get("type", "Unknown")
        c = parsed.get("cause", "Unknown cause")
        f = parsed.get("fix", "")

        # 🔥 fallback fix if weak
        if not f or "investigation" in f.lower():
            f = "Check service dependencies, permissions, and related subsystem logs"

        return t, c, f

    except Exception as e:
        print("AI ERROR:", e)
        return "Unknown", "AI call failed", "Check Ollama server"


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

    for i,(pattern,occ) in enumerate(groups.items(), start=1):

        count = len(occ)
        sample = occ[0].lower()

        print(f"[{i}/{len(groups)}] pattern count:", count)

        # ---------------- RULE BASED ----------------
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
            c="Service unable to access active user session token"
            f="Ensure service has required permissions and session access"

        elif "instance" in sample or "manager" in sample:
            t="Service Initialization Error"
            c="Required module or service instance not available"
            f="Check service startup order and dependencies"

        else:
            # ---------------- AI ----------------
            t, c, f = ollama_analyze(sample)

        cards.append({
            "error_line": sample,
            "type": t,
            "cause": c,
            "fix": f,
            "count": count
        })

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
