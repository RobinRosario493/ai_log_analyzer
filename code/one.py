from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import re
import os
import subprocess
import requests
from collections import defaultdict
from ai_engine import analyze_patterns_with_ai
import json

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:8b"
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
PDB_UPLOAD_DIR = "uploaded_pdbs"
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)



# =========================================================
# ---------------- AI BULK ANALYZER ----------------
# =========================================================
def ai_bulk_analyze(samples):
    """
    Production AI log classifier.
    - Forces specific error types
    - Uses structured JSON
    - Prevents generic 'error'
    - Gives better cause & fix
    """

    prompt = f"""
You are a senior systems debugging engineer.

For each log entry, diagnose the real technical issue.

Identify:
- The failing component
- The failure mechanism
- The root cause
- The precise corrective action

Be technical and specific.
Use module names, error codes, and context when available.
Avoid vague explanations.

Return ONLY valid JSON in this format:

[
 {{
  "pattern": "...exact log text...",
  "type": "...short technical failure name...",
  "cause": "...clear root cause...",
  "fix": "...direct corrective action...",
  "severity": "Low/Medium/High"
 }}
]

LOGS:
{samples}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9
                }
            },
            timeout=600
        )

        text = r.json().get("response", "").strip()

        # -------- extract JSON safely --------
        start = text.find("[")
        end = text.rfind("]") + 1

        if start == -1 or end == -1:
            print("AI returned non-JSON:", text[:300])
            return []

        text = text[start:end]
        data = json.loads(text)

        # -------- ensure fields exist --------
        cleaned = []
        for item in data:
            cleaned.append({
                "pattern": item.get("pattern", ""),
                "type": item.get("type", "Unknown"),
                "cause": item.get("cause", "Unknown"),
                "fix": item.get("fix", "Check logs"),
                "severity": item.get("severity", "Medium")
            })

        return cleaned

    except Exception as e:
        print("AI parse fail:", e)
        return []


def ai_retry_single(sample):
    return ai_bulk_analyze([sample])


# =========================================================
# ---------------- DATABASE ----------------
# =========================================================
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

LAST_LOG_RESULTS = []


# =========================================================
# ---------------- HOME ----------------
# =========================================================
@app.route("/")
def home():
    return render_template("one.html")


# =========================================================
# ---------------- LOG ANALYZER ----------------
# =========================================================
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    return line.strip()


def analyze_errors_only(log_text, filename):

    lines = log_text.split("\n")
    groups = defaultdict(list)
    total_errors = 0

    # -------- GROUP ERRORS --------
    for i, line in enumerate(lines):
        if any(x in line.lower() for x in ["error", "failed", "exception", "fatal"]):
            total_errors += 1
            key = normalize(line)
            groups[key].append((i, line))

    if total_errors == 0:
        return {"file": filename, "total_errors": 0, "analysis": []}

    patterns = list(groups.items())
    samples = [occ[0][1] for _, occ in patterns]

    print(f"{filename} → Sending {len(samples)} patterns to AI")

    ai_results = ai_bulk_analyze(samples)
    print("AI returned:", len(ai_results))

    ai_map = {}
    for r in ai_results:
        if "pattern" in r:
            ai_map[normalize(r["pattern"])] = r

    cards = []

    # -------- BUILD CARDS --------
    for pattern, occ in patterns:

        sample = occ[0][1]
        count = len(occ)
        key_norm = normalize(sample)

        if key_norm in ai_map:
            r = ai_map[key_norm]
            t = r.get("type", "Unknown")
            c = r.get("cause", "Unknown")
            f = r.get("fix", "Unknown")
            sev = r.get("severity", "Medium")

        else:
            print("Retry AI for missing pattern...")
            retry = ai_retry_single(sample)

            if retry:
                r = retry[0]
                t = r.get("type", "Unknown")
                c = r.get("cause", "Unknown")
                f = r.get("fix", "Unknown")
                sev = r.get("severity", "Medium")
            else:
                t = "AI Uncertain"
                c = "Model couldn't classify"
                f = "Check log manually"
                sev = "Low"

        cards.append({
            "file": filename,
            "error_line": sample,
            "type": t,
            "cause": c,
            "fix": f,
            "count": count,
            "status": "Active",
            "severity": sev
        })

    return {
        "file": filename,
        "total_errors": total_errors,
        "analysis": cards
    }


@app.route("/analyze_logs", methods=["POST"])
def analyze_logs():

    global LAST_LOG_RESULTS
    LAST_LOG_RESULTS = []

    files = request.files.getlist("logfile")

    for file in files:
        text = file.read().decode("utf-8", "ignore")
        result = analyze_errors_only(text, file.filename)
        LAST_LOG_RESULTS.append(result)

    return jsonify({"files": LAST_LOG_RESULTS})


# =========================================================
# ---------------- DUMP ANALYZER ----------------
# =========================================================
def run_windbg(dump_path, pdb_path=None):

    log_file = "windbg_output.txt"

    cmd = [
        WINDBG,
        "-z", dump_path,
    ]

    # If PDB is provided, tell WinDbg where symbols are
    if pdb_path:
        cmd += ["-y", PDB_UPLOAD_DIR]


    cmd += [
        "-logo", log_file,
        "-c", "!analyze -v; q"
    ]

    subprocess.run(cmd, timeout=300)

    if os.path.exists(log_file):
        with open(log_file, "r", errors="ignore") as f:
            return f.read()

    return ""


def extract_dump_section(text):
    start = text.find("BugCheck")
    if start == -1:
        return text[:6000]
    return text[start:start + 6000]


def analyze_dump_ai(text):

    clean = extract_dump_section(text)

    prompt = f"""
You are a Windows crash dump expert.

From this crash dump provide:
- Bugcheck
- Faulty driver/module
- Root cause
- Fix

Crash Output:
{clean}
"""

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=300
    )

    return r.json().get("response", "")


@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    dump_files = request.files.getlist("dumpfile")
    pdb_files = request.files.getlist("pdbfile")

    results = []

    for i, dump in enumerate(dump_files):

        dump_name = dump.filename
        dump_path = "temp_" + dump_name
        dump.save(dump_path)

        pdb_path = None

        # If user uploaded a PDB for this dump
        if i < len(pdb_files):
            pdb = pdb_files[i]

            if pdb.filename.endswith(".pdb"):
                pdb_path = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdb_path)

        # Run WinDbg
        text = run_windbg(dump_path, pdb_path)
        ai = analyze_dump_ai(text)

        results.append({
            "file": dump_name,
            "pdb_used": pdb_path if pdb_path else "None",
            "analysis": ai
        })

    return jsonify({"files": results})



# =========================================================
# ---------------- ASK AI ----------------
# =========================================================
@app.route("/ask_ai", methods=["POST"])
def ask_ai():

    data = request.json
    error = data.get("error", "")

    prompt = f"""
Explain this log error clearly and give fix:

{error}
"""

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=60
    )

    return jsonify({"answer": r.json().get("response", "")})


# =========================================================
# ---------------- CHATBOT ----------------
# =========================================================
@app.route("/chat", methods=["POST"])
def chat():

    data = request.json
    msg = data.get("message", "")

    summary = str(LAST_LOG_RESULTS)[:2000]

    prompt = f"""
You are support AI.

Log summary:
{summary}

User:
{msg}
"""

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=60
    )

    reply = r.json().get("response", "")

    conn = sqlite3.connect("chat_history.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chat_messages (user_message, ai_reply) VALUES (?,?)",
        (msg, reply)
    )
    conn.commit()
    conn.close()

    return jsonify({"reply": reply})


# =========================================================
if __name__ == "__main__":
    print("UNIFIED ANALYZER STARTED")
    app.run(host="127.0.0.1", port=5000, debug=True)
