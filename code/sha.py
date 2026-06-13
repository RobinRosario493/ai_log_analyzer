from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import re
from collections import defaultdict
from ai_engine import analyze_patterns_with_ai
import requests

app = Flask(__name__, template_folder="templates")
CORS(app)

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect("chat_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_message TEXT,
            ai_reply TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("sha.html")

# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'^\d{2}/\d{2}/\d{4}.*?:', '', line)
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- RECOVERY DETECTION ----------------
def is_recovery_line(line):
    recovery_keywords = [
        "success", "successfully", "restored", "recovered",
        "connected", "connection established",
        "retry succeeded", "mounted successfully"
    ]
    return any(x in line.lower() for x in recovery_keywords)

# ---------------- LOG ANALYSIS ----------------
def analyze_errors_only(log_text):

    lines = log_text.split("\n")
    total_errors = 0
    groups = defaultdict(list)

    for index, line in enumerate(lines):
        if any(x in line.lower() for x in ["error", "exception", "failed", "critical", "fatal"]):
            total_errors += 1
            key = normalize(line)
            groups[key].append((index, line))

    if total_errors == 0:
        return {"total_errors": 0, "analysis": []}

    patterns = list(groups.items())
    cards = []

    chunk_size = 2  # Stable for llama3:8b

    for i in range(0, len(patterns), chunk_size):

        chunk = patterns[i:i + chunk_size]
        samples = [occ[0][1].lower() for _, occ in chunk]

        print(f"Processing AI batch {i//chunk_size + 1}")

        ai_results = analyze_patterns_with_ai(samples)

        for idx, (pattern, occ) in enumerate(chunk):

            count = len(occ)
            first_index = occ[0][0]
            sample = occ[0][1].lower()

            status = "Active"
            check_range = lines[first_index:first_index + 8]

            for l in check_range:
                if is_recovery_line(l):
                    status = "Resolved"
                    break

            if idx < len(ai_results):
                result = ai_results[idx]

                t = result.get("type") or "Unknown"
                c = result.get("cause") or "Unknown"

                f = result.get("fix")
                if not f or len(f.strip()) < 5:
                    f = "Check permissions, service configuration, and system logs."

                severity = result.get("severity") or "Medium"
            else:
                t = "Unknown"
                c = "AI response missing"
                f = "Manual investigation required"
                severity = "Medium"

            if status == "Resolved":
                c = ""
                f = ""

            cards.append({
                "error_line": sample,
                "type": t,
                "cause": c,
                "fix": f,
                "count": count,
                "status": status,
                "severity": severity
            })

    return {
        "total_errors": total_errors,
        "analysis": cards
    }

# ---------------- ANALYZE ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():

    if request.files and "logfile" in request.files:
        file = request.files["logfile"]
        log_text = file.read().decode("utf-8", errors="ignore")
    else:
        return jsonify({"error": "No log file provided"}), 400

    result = analyze_errors_only(log_text)
    return jsonify(result)

# ---------------- CHAT ROUTE ----------------
@app.route("/chat", methods=["POST"])
def chat():

    data = request.json
    user_message = data.get("message", "")

    if not user_message:
        return jsonify({"reply": "No message provided."})

    prompt = f"""
You are an expert system diagnostic AI assistant.

IMPORTANT:
- Do NOT return JSON.
- Do NOT return structured format.
- Respond in plain English only.
- Maximum 6 lines.
- Be clear and professional.

User Question:
{user_message}
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3:8b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "top_p": 0.1,
                    "num_predict": 250
                }
            },
            timeout=120
        )

        result = response.json()
        reply = result.get("response", "")

        conn = sqlite3.connect("chat_history.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO chat_messages (user_message, ai_reply) VALUES (?, ?)",
            (user_message, reply)
        )
        conn.commit()
        conn.close()

        return jsonify({"reply": reply})

    except Exception:
        return jsonify({"reply": "AI service unavailable."})

# ---------------- RUN ----------------
if __name__ == "__main__":
    print("Starting Flask Server...")
    app.run(host="127.0.0.1", port=5000, debug=True)