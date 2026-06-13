from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import uuid
import json
import sqlite3
import requests
import re
from datetime import datetime
from collections import defaultdict

# ---------------- CONFIG ----------------

MODEL = "llama3:8b"
OLLAMA_URL = "http://localhost:11434/api/generate"

REPORT_ROOT = "analysis_reports"
PDB_UPLOAD_DIR = "uploaded_pdbs"

os.makedirs(REPORT_ROOT, exist_ok=True)
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)

# ---------------- GLOBAL JOB STATE ----------------

CURRENT_JOB = {
    "id": None,
    "path": None,
    "results": [],
    "cancelled": False
}

# ---------------- APP INIT ----------------

app = Flask(__name__, template_folder="templates")
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

# ---------------- JOB MANAGER ----------------

def start_investigation():

    if CURRENT_JOB["id"] and CURRENT_JOB["path"]:
        return CURRENT_JOB["path"]

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    job_id = f"JOB_{timestamp}_{uuid.uuid4().hex[:6]}"

    job_path = os.path.join(REPORT_ROOT, job_id)

    os.makedirs(job_path, exist_ok=True)

    for folder in ["logs", "dotlogs", "etl", "dumps", "reports"]:
        os.makedirs(os.path.join(job_path, folder), exist_ok=True)

    CURRENT_JOB["id"] = job_id
    CURRENT_JOB["path"] = job_path
    CURRENT_JOB["results"] = []
    CURRENT_JOB["cancelled"] = False

    return job_path


def end_investigation():

    CURRENT_JOB["id"] = None
    CURRENT_JOB["path"] = None
    CURRENT_JOB["results"] = []
    CURRENT_JOB["cancelled"] = False

# ---------------- DATABASE ----------------

def init_db():

    conn = sqlite3.connect("chat_history.db")

    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS chatmessages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usermessage TEXT,
        aireply TEXT
    )
    """)

    conn.commit()

    conn.close()


init_db()

# ---------------- AI ENGINE ----------------

def call_ai(prompt, timeout=180):

    try:

        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2}
            },
            timeout=timeout
        )

        return r.json().get("response", "").strip()

    except requests.exceptions.Timeout:
        return "AI timeout."

    except Exception as e:
        print("AI error:", e)
        return ""


# ---------------- SAFE JSON PARSER ----------------

def extract_json(text):

    if not text:
        return None

    text = text.replace("```json", "").replace("```", "")

    match = re.search(r'\{.*?\}', text, re.DOTALL)

    if match:
        try:
            return json.loads(match.group())
        except:
            return None

    return None


# ---------------- HTML REPORT GENERATOR ----------------

def save_html_report(output_path, file_name, analysis_cards):

    html = f"""
<html>
<head>
<title>Analysis Report - {file_name}</title>

<style>

body {{
font-family: Arial;
background:#0f172a;
color:white;
padding:30px;
}}

.card {{
background:#1e293b;
padding:15px;
margin:15px 0;
border-radius:8px;
}}

.high {{ color:red; }}
.medium {{ color:orange; }}
.low {{ color:lightgreen; }}
.info {{ color:lightblue; }}

</style>

</head>

<body>

<h1>File Analysis Report</h1>
<h2>{file_name}</h2>

<hr>

"""

    if not analysis_cards:
        html += "<p>No issues detected.</p>"

    for card in analysis_cards:

        severity = card.get("severity", "Low").lower()

        html += f"""
<div class="card">

<b>Type:</b> {card.get("type","")} <br>
<b>Severity:</b> <span class="{severity}">{card.get("severity","")}</span> <br>
<b>Occurrences:</b> {card.get("count",1)} <br><br>

<b>Cause:</b><br>
{card.get("cause","")} <br><br>

<b>Fix:</b><br>
{card.get("fix","")}

</div>
"""

    html += """
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------- NORMALIZATION ----------------

def normalize_text(text):

    if not text:
        return ""

    text = text.lower()

    text = re.sub(r'0x[0-9a-fA-F]+', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


# ---------------- CHAT ENGINE ----------------

@app.route("/chat", methods=["POST"])
def chat():

    data = request.json

    message = data.get("message", "")

    investigation_summary = str(CURRENT_JOB["results"])[-3000:]

    prompt = f"""
Investigation data:

{investigation_summary}

User question:
{message}
"""

    reply = call_ai(prompt)

    conn = sqlite3.connect("chat_history.db")

    cur = conn.cursor()

    cur.execute(
        "INSERT INTO chatmessages (usermessage, aireply) VALUES (?,?)",
        (message, reply)
    )

    conn.commit()
    conn.close()

    return jsonify({"reply": reply})


# ---------------- STATUS ROUTES ----------------

@app.route("/")
def home():

    return render_template("dashboard.html")


@app.route("/job_status")
def job_status():

    return jsonify({
        "job_id": CURRENT_JOB["id"],
        "files_analyzed": len(CURRENT_JOB["results"]),
        "cancelled": CURRENT_JOB["cancelled"]
    })


@app.route("/cancel_analysis")
def cancel_analysis():

    CURRENT_JOB["cancelled"] = True

    return jsonify({"status": "cancelled"})


# ---------------- PLACEHOLDER ENDPOINTS ----------------

# These will be fully implemented in Part 2

@app.route("/analyze_logs", methods=["POST"])
def analyze_logs():

    return jsonify({"message": "Log analyzer loaded in Part 2"})


@app.route("/analyze_dotlogs", methods=["POST"])
def analyze_dotlogs():

    return jsonify({"message": ".log analyzer loaded in Part 2"})


@app.route("/analyze_etl", methods=["POST"])
def analyze_etl():

    return jsonify({"message": "ETL analyzer loaded in Part 2"})


@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    return jsonify({"message": "Dump analyzer loaded in Part 2"})


@app.route("/final_correlation")
def final_correlation():

    return jsonify({"message": "Correlation engine loaded in Part 3"})


# ---------------- RUN SERVER ----------------

if __name__ == "__main__":

    print("AI Diagnostics Platform Started")

    app.run(host="127.0.0.1", port=5000, debug=True)