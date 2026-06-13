from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import os
import subprocess
import requests
from collections import defaultdict
import json
import re

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:8b"
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
PDB_UPLOAD_DIR = "uploaded_pdbs"
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)
def call_ai(prompt, timeout=120):
    """
    Safe AI caller for chat + ask_ai
    prevents hanging and always returns text
    """
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=timeout
        )

        data = r.json()
        return data.get("response", "").strip()

    except requests.exceptions.Timeout:
        return "AI timeout. Model is busy analyzing logs."

    except Exception as e:
        print("AI ERROR:", e)
        return "AI service error."

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect("chat_history.db")
    cur = conn.cursor()
    cur.execute("""
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

# ================= HOME =================
@app.route("/")
def home():
    return render_template("event.html")

# =========================================================
# 🧠 AI CALL
# =========================================================
def ai_bulk_analyze(samples):

    if not samples:
        return []

    prompt = f"""
You are a senior Windows kernel and systems debugging engineer.

For each log event:
- Identify subsystem (VSS, SPP, .NET, Service, Kernel, Certificate, etc)
- Identify failure mechanism
- Identify root cause
- Provide exact corrective action
- Assign severity

STRICT RULES:
- Do NOT return generic type "Error"
- Use technical names
- Be precise
- Return ONLY JSON array

FORMAT:
[
 {{
  "pattern": "...",
  "type": "...technical failure name...",
  "cause": "...root cause...",
  "fix": "...precise fix...",
  "severity": "Low/Medium/High"
 }}
]

LOG EVENTS:
{chr(10).join(samples)}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}
            },
            timeout=600
        )

        text = r.json().get("response", "")

        start = text.find("[")
        end = text.rfind("]")

        if start == -1 or end == -1:
            print("AI JSON parse fail")
            print(text[:400])
            return []

        return json.loads(text[start:end+1])

    except Exception as e:
        print("AI call error:", e)
        return []

# =========================================================
# 🔍 EVENT VIEWER ANALYZER
# =========================================================
def extract_signature(msg):
    m = msg.lower()

    if "nullreferenceexception" in m:
        return "NullReferenceException"
    if "vss" in m:
        return "VSSFailure"
    if "certificate" in m or "scep" in m:
        return "CertificateFailure"
    if "license" in m or "spp" in m:
        return "LicenseFailure"
    if "application hang" in m:
        return "AppHang"

    return m[:120]

def get_context(lines, index, window=3):
    start = max(0, index-window)
    end = min(len(lines), index+window+1)
    return " ".join(lines[start:end])

def normalize_message(msg):
    m = msg.lower()

    # remove timestamps like 12:34:56
    m = re.sub(r"\d{2}:\d{2}:\d{2}", "", m)

    # remove standalone numbers
    m = re.sub(r"\b\d+\b", "", m)

    # normalize hex codes
    m = re.sub(r"0x[0-9a-f]+", "0xCODE", m)

    # remove GUIDs
    m = re.sub(r"[0-9a-f\-]{36}", "GUID", m)

    # collapse spaces
    m = re.sub(r"\s+", " ", m)

    return m.strip()

def analyze_errors_only(log_text, filename):

    lines = log_text.splitlines()
    grouped = defaultdict(list)
    total_errors = 0

    for i, line in enumerate(lines):

        if not line.lower().startswith("error"):
            continue

        total_errors += 1

        parts = line.split()

        # safe extraction
        source = parts[3] if len(parts) >= 4 else "generic"
        event_id = parts[4] if len(parts) >= 5 else "0"

        # 🔴 NEW: normalize message for grouping
        normalized = normalize_message(line)

        # 🔴 GROUP ONLY BY SOURCE + EVENT ID + NORMALIZED PATTERN
        key = f"{source}_{event_id}_{normalized[:80]}"
        grouped[key].append((i, line))

    if total_errors == 0:
        return {"file": filename, "total_errors": 0, "analysis": []}

    samples = []
    keys = []

    for key, rows in grouped.items():
        idx, sample_line = rows[0]
        context = get_context(lines, idx)
        samples.append(context)
        keys.append(key)

    print(f"{filename} → unique groups:", len(samples))

    # ---------- AI BATCH ----------
    ai_results = []
    batch_size = 3

    for i in range(0, len(samples), batch_size):
        chunk = samples[i:i+batch_size]
        print("AI batch", i//batch_size + 1)
        res = ai_bulk_analyze(chunk)
        ai_results.extend(res)

    ai_map = {}
    for k, r in zip(keys, ai_results):
        ai_map[k] = r

    cards = []

    for key, rows in grouped.items():

        sample = rows[0][1]
        count = len(rows)

        r = ai_map.get(key, {})

        cards.append({
            "file": filename,
            "error_line": sample,
            "type": r.get("type", "System Failure"),
            "cause": r.get("cause", "Unknown"),
            "fix": r.get("fix", "Check logs"),
            "count": count,
            "status": "Active",
            "severity": r.get("severity", "Medium")
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
# 💀 DUMP ANALYZER (UNCHANGED)
# =========================================================
def run_windbg(dump_path, pdb_path=None):

    log_file = "windbg_output.txt"
    cmd = [WINDBG, "-z", dump_path]

    if pdb_path:
        cmd += ["-y", PDB_UPLOAD_DIR]

    cmd += ["-logo", log_file, "-c", "!analyze -v; q"]
    subprocess.run(cmd, timeout=300)

    if os.path.exists(log_file):
        with open(log_file, "r", errors="ignore") as f:
            return f.read()

    return ""

def analyze_dump_ai(text):

    prompt = f"""
You are a senior Windows kernel crash dump analyst.

You are given WinDbg output from `!analyze -v`.

Extract REAL technical information.

DO NOT give generic advice.
DO NOT say "run !analyze -v".
You are the analyzer.

Your job:

1. Identify BUGCHECK code
2. Identify FAULTING DRIVER (Probably caused by)
3. Identify IMAGE_NAME or MODULE_NAME
4. Identify subsystem (GPU, network, storage, etc)
5. Explain exact root cause
6. Give precise fix (driver update, rollback, patch)
7. Be specific and technical

Return in this format:

BUGCHECK:
FAULTING_DRIVER:
SUBSYSTEM:
ROOT_CAUSE:
FIX:

WINDBG OUTPUT:
{text[:8000]}
"""

    return call_ai(prompt, timeout=300)

@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    dump_files = request.files.getlist("dumpfile")
    pdb_files = request.files.getlist("pdbfile")

    results = []

    for i, dump in enumerate(dump_files):

        path = "temp_" + dump.filename
        dump.save(path)

        pdb_path = None
        if i < len(pdb_files):
            pdb = pdb_files[i]
            if pdb.filename.endswith(".pdb"):
                pdb_path = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdb_path)

        text = run_windbg(path, pdb_path)
        ai = analyze_dump_ai(text)

        results.append({
            "file": dump.filename,
            "analysis": ai
        })

    return jsonify({"files": results})

# =========================================================
# 🤖 ASK AI
# =========================================================
@app.route("/ask_ai", methods=["POST"])
def ask_ai():
    try:
        data = request.get_json(force=True)
        error = data.get("error", "")

        if not error:
            return jsonify({"answer": "No error text provided"})

        prompt = f"""
You are a senior Windows debugging engineer.

Explain this error clearly and provide exact fix:

{error}
"""

        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2}
            },
            timeout=120
        )

        reply = r.json().get("response", "").strip()

        if not reply:
            reply = "AI returned empty response."

        return jsonify({"answer": reply})

    except requests.exceptions.Timeout:
        return jsonify({"answer": "AI timeout. Try again."})

    except Exception as e:
        print("ASK AI ERROR:", e)
        return jsonify({"answer": "AI service error"})

# =========================================================
# 💬 CHATBOT
# =========================================================
@app.route("/chat", methods=["POST"])
def chat():

    data = request.json
    msg = data.get("message", "")

    summary = str(LAST_LOG_RESULTS)[:3000]

    prompt = f"""
You are a system debugging assistant.

Current analyzed logs:
{summary}

User question:
{msg}

Answer clearly and technically.
"""

    reply = call_ai(prompt)

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