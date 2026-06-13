from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import os
import subprocess
import requests
from collections import defaultdict
import json
import csv
from io import StringIO
from collections import defaultdict
from datetime import datetime
import re

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:8b"
OLLAMA_URL = "http://localhost:11434/api/generate"

WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
PDB_UPLOAD_DIR = "uploaded_pdbs"
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

LASTLOGRESULTS = []

# ---------------- AI CALL ----------------
def callai(prompt, timeout=120):
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
        print("AI ERROR:", e)
        return "AI service error."


# ---------------- DB ----------------
def initdb():
    conn = sqlite3.connect("chathistory.db")
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

initdb()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("etl.html")

# ---------------- AI BULK ANALYZE ----------------
def aibulkanalyze(samples):
    if not samples:
        return []

    prompt = f"""
You are a senior Windows debugging engineer.

For each log event return JSON:
type, cause, fix, severity.

Return ONLY JSON array.

LOG EVENTS:
{chr(10).join(samples)}
"""

    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}
            },
            timeout=600
        )

        text = r.json().get("response", "").strip()

        try:
            return json.loads(text)
        except:
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1:
                return json.loads(text[start:end+1])
            print("AI JSON parse failed:", text)
            return []

    except Exception as e:
        print("AI call error:", e)
        return []

# ---------------- HELPERS ----------------
def extractsignature(msg):
    m = msg.lower()
    if "nullreferenceexception" in m:
        return "NullReferenceException"
    if "vss" in m:
        return "VSSFailure"
    if "certificate" in m:
        return "CertificateFailure"
    if "license" in m:
        return "LicenseFailure"
    return m[:120]

def getcontext(lines, index, window=3):
    start = max(0, index - window)
    end = min(len(lines), index + window + 1)
    return " ".join(lines[start:end])

# ---------------- CORE LOG ANALYSIS ----------------
def analyzeerrorsonly(logtext, filename):
    lines = logtext.splitlines()
    grouped = defaultdict(list)
    total_errors = 0

    ERROR_WORDS = [
        "error","fail","failed","exception",
        "critical","timeout","denied","crash"
    ]

    for i, line in enumerate(lines):
        l = line.lower()

        # ONLY process error lines
        if not any(w in l for w in ERROR_WORDS):
            continue

        key = normalize_log(line)[:120]
        groups[key].append((i, line))

        if not any(word in l for word in [
            "error","fail","failed","critical",
            "exception","0x","denied",
            "timeout","unable","crash"
        ]):
            continue

        total_errors += 1

        parts = line.split()
        source = parts[3] if len(parts) >= 4 else "Unknown"
        eventid = parts[4] if len(parts) >= 5 else "0"

        signature = extractsignature(line)
        key = f"{source}{eventid}{signature}"
        grouped[key].append((i, line))

    if total_errors == 0:
        return {"file": filename, "total_errors": 0, "analysis": []}

    samples, keys = [], []

    for key, rows in grouped.items():
        idx, sampleline = rows[0]
        context = getcontext(lines, idx)
        samples.append(context)
        keys.append(key)

    airesults = []
    batchsize = 6

    for i in range(0, len(samples), batchsize):
        chunk = samples[i:i+batchsize]
        res = aibulkanalyze(chunk)
        airesults.extend(res)

    aimap = {}
    for k, r in zip(keys, airesults):
        aimap[k] = r

    cards = []

    for key, rows in grouped.items():
        sample = rows[0][1]
        count = len(rows)

        r = aimap.get(key, {})

        cards.append({
            "file": filename,
            "error_line": sample,
            "type": r.get("type", "Unknown"),
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

# ---------------- LOG ROUTE ----------------
@app.route("/analyze_logs", methods=["POST"])
def analyze_logs():
    global LASTLOGRESULTS
    LASTLOGRESULTS = []

    files = request.files.getlist("logfile")

    for file in files:
        text = file.read().decode("utf-8", "ignore")
        result = analyzeerrorsonly(text, file.filename)
        LASTLOGRESULTS.append(result)

    return jsonify({"files": LASTLOGRESULTS})




# ================= DOT LOG ANALYZER =================

from concurrent.futures import ThreadPoolExecutor

AI_CACHE = {}

ERROR_WORDS = [
    "error","fail","failed","exception",
    "critical","timeout","denied","crash"
]

# ---------- NORMALIZE ----------
def normalize_log(line):
    line = line.lower()
    line = re.sub(r'\[.*?\]', '', line)
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'[0-9a-fA-F-]{36}', 'GUID', line)
    return line.strip()


# ---------- AI CLASSIFIER ----------
def analyze_log_patterns_with_ai(samples):

    prompt = f"""
    Classify each log into:

    type → technical failure category (NOT 'Error' or 'Information')
    cause → root cause
    fix → actionable fix
    severity → Low/Medium/High

    Return ONLY JSON array.

    LOGS:
    {chr(10).join(samples)}
    """

    text = callai(prompt, timeout=120)

    try:
        text = text.replace("```json","").replace("```","").strip()

        start = text.find("[")
        end = text.rfind("]")

        if start != -1 and end != -1:
            data = json.loads(text[start:end+1])
        else:
            return []

        for d in data:
            if "severity" in d:
                d["severity"] = d["severity"].capitalize()

        return data

    except Exception as e:
        print("AI parse error:", e)
        return []


# ---------- MAIN ANALYZER ----------
def analyze_dotlog_file(log_text, filename):

    lines = log_text.splitlines()
    groups = defaultdict(list)

    # -------- FILTER + GROUP --------
    for i, line in enumerate(lines):
        l = line.lower()

        if not any(w in l for w in ERROR_WORDS):
            continue

        key = normalize_log(line)[:120]
        groups[key].append((i, line))

    print("TOTAL ERROR GROUPS:", len(groups))

    # -------- LIMIT PATTERNS --------
    MAX_PATTERNS = 40

    samples = []
    keys = []

    for key, occ in groups.items():
        if len(samples) >= MAX_PATTERNS:
            break
        samples.append(occ[0][1])
        keys.append(key)

    print("SAMPLES SENT TO AI:", len(samples))

    # -------- CACHE CHECK --------
    uncached_samples = []
    uncached_keys = []

    for k, s in zip(keys, samples):
        if k not in AI_CACHE:
            uncached_samples.append(s)
            uncached_keys.append(k)

    # -------- AI CALLS (SEQUENTIAL FOR STABILITY) --------
    batch = 8

    for i in range(0, len(uncached_samples), batch):
        chunk = uncached_samples[i:i+batch]
        chunk_keys = uncached_keys[i:i+batch]

        print("AI CALL FOR", len(chunk), "patterns")

        res = analyze_log_patterns_with_ai(chunk)

        for idx, k in enumerate(chunk_keys):
            if idx < len(res):
                AI_CACHE[k] = res[idx]

    # -------- BUILD CARDS --------
    cards = []

    for key, occ in groups.items():

        if key not in AI_CACHE:
            continue

        r = AI_CACHE[key]
        severity = r.get("severity", "Low")

        if severity == "Low":
            continue

        cards.append({
            "file": filename,
            "error_line": occ[0][1],
            "type": r.get("type","Unknown"),
            "cause": r.get("cause","Unknown"),
            "fix": r.get("fix","Check manually"),
            "count": len(occ),
            "status": "Active",
            "severity": severity
        })

    return {
        "file": filename,
        "total_errors": sum(len(v) for v in groups.values()),
        "analysis": cards
    }


# ---------- ROUTE ----------
@app.route("/analyze_dotlogs", methods=["POST"])
def analyze_dotlogs():

    results = []
    files = request.files.getlist("logfile")

    for file in files:
        text = file.read().decode("utf-8","ignore")
        result = analyze_dotlog_file(text, file.filename)
        results.append(result)

    return jsonify({"files": results})
# ---------------- WINDBG ----------------
def runwindbg(dumppath, pdbpath=None):
    logfile = "windbgoutput.txt"
    cmd = [WINDBG, "-z", dumppath]

    if pdbpath:
        cmd += ["-y", PDB_UPLOAD_DIR]

    cmd += ["-logo", logfile, "-c", "!analyze -v; q"]

    try:
        subprocess.run(cmd, timeout=300)
    except Exception as e:
        print("WinDbg error:", e)

    if os.path.exists(logfile):
        with open(logfile, "r", errors="ignore") as f:
            return f.read()

    return ""

def analyzedumpai(text):
    prompt = f"""
You are a senior Windows kernel crash dump analyst.

You are given WinDbg output from !analyze -v.

Extract REAL technical information.

DO NOT give generic advice.
DO NOT say "run !analyze -v".
You are the analyzer.

Your task:
1. Identify BUGCHECK code
2. Identify FAULTING DRIVER (Probably caused by)
3. Identify IMAGE_NAME or MODULE_NAME
4. Identify subsystem (GPU, network, storage, etc)
5. Explain exact root cause
6. Give precise fix (driver update, rollback, patch)
7. Be specific and technical

Return in this structured format:

BUGCHECK:
FAULTING_DRIVER:
SUBSYSTEM:
ROOT_CAUSE:
FIX:

WINDBG OUTPUT:
{text[:8000]}
"""
    return callai(prompt, timeout=300)

# ---------------- DUMP ROUTE ----------------
@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():
    dumpfiles = request.files.getlist("dumpfile")
    pdbfiles = request.files.getlist("pdbfile")

    results = []

    for i, dump in enumerate(dumpfiles):
        path = "temp_" + dump.filename
        dump.save(path)

        pdbpath = None
        if i < len(pdbfiles):
            pdb = pdbfiles[i]
            if pdb.filename.endswith(".pdb"):
                pdbpath = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdbpath)

        text = runwindbg(path, pdbpath)
        ai = analyzedumpai(text)

        results.append({"file": dump.filename, "analysis": ai})

        if os.path.exists(path):
            os.remove(path)

    return jsonify({"files": results})

# ---------------- ASK AI ----------------
@app.route("/ask_ai", methods=["POST"])
def ask_ai():
    data = request.get_json(force=True)
    error = data.get("error", "")

    if not error:
        return jsonify({"answer": "No error text provided"})

    reply = callai(f"Explain this error and fix:\n{error}")
    return jsonify({"answer": reply})

# ---------------- CHAT ----------------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    msg = data.get("message", "")

    summary = str(LASTLOGRESULTS)[:3000]

    prompt = f"""
Logs:
{summary}

User:
{msg}
"""

    reply = callai(prompt)

    conn = sqlite3.connect("chathistory.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chatmessages (usermessage, aireply) VALUES (?,?)",
        (msg, reply)
    )
    conn.commit()
    conn.close()

    return jsonify({"reply": reply})

# ---------------- ETL ----------------
def convert_etl_to_text(etl_path):
    out_csv = etl_path + "_decoded.csv"

    cmd = [
        "powershell",
        "-Command",
        f"""
        Get-WinEvent -Path '{etl_path}' -Oldest |
        Select TimeCreated, ProviderName, Id, Message |
        Export-Csv '{out_csv}' -NoTypeInformation
        """
    ]

    try:
        subprocess.run(cmd, timeout=600)
    except Exception as e:
        print("ETL decode error:", e)
        return ""

    if os.path.exists(out_csv):
        with open(out_csv, "r", errors="ignore") as f:
            return f.read()

    return ""



def analyze_etl_behavior(csv_text, filename):
    reader = csv.DictReader(StringIO(csv_text))
    rows = list(reader)

    if not rows:
        return {"file": filename, "patterns": []}

    patterns = []
    provider_counts = defaultdict(int)

    timestamps = []

    for r in rows:
        msg = (r.get("Message") or "").lower()
        provider = r.get("ProviderName", "Unknown")

        provider_counts[provider] += 1

        t = r.get("TimeCreated")
        if t:
            try:
                timestamps.append(datetime.fromisoformat(t))
            except:
                pass

        # retry detection
        if "retry" in msg:
            patterns.append(("Retry activity detected", msg))

        # crash keywords
        if any(w in msg for w in ["crash","stopped unexpectedly","bugcheck"]):
            patterns.append(("Crash indicator", msg))

        # timeout
        if "timeout" in msg:
            patterns.append(("Timeout detected", msg))

    # loop detection
    for provider, count in provider_counts.items():
        if count > 50:
            patterns.append(("High activity loop", provider))

    # gap detection
    if len(timestamps) > 2:
        gaps = [
            (timestamps[i] - timestamps[i-1]).total_seconds()
            for i in range(1, len(timestamps))
        ]
        if max(gaps) > 60:
            patterns.append(("Long delay detected", "Gap >60s"))

    if not patterns:
        patterns.append(("Normal behavior", "No anomalies detected"))

    return {
        "file": filename,
        "patterns": patterns
    }

def analyze_etl_with_ai(patterns):
    samples = [p[0] + " : " + p[1] for p in patterns[:10]]

    prompt = f"""
You are a Windows ETL diagnostics expert.

Only explain what can be proven from the patterns.
Do NOT assume CPU, disk, or network issues unless explicitly stated.

Return JSON:
type, cause, fix, severity.

Patterns:
{chr(10).join(samples)}
"""

    return callai(prompt)

@app.route("/analyze_etl", methods=["POST"])
def analyze_etl():
    files = request.files.getlist("etlfile")
    results = []

    for file in files:
        name = file.filename
        temp = "temp_" + name
        file.save(temp)

        csv_text = convert_etl_to_text(temp)

        if not csv_text:
            results.append({
                "file": name,
                "total_errors": 0,
                "analysis": []
            })
        else:
            behavior = analyze_etl_behavior(csv_text, name)

            # If no patterns detected, mark as normal
            if not behavior["patterns"]:
                behavior["patterns"] = [("Normal behavior detected", "No anomalies found in ETL trace")]

            ai_text = analyze_etl_with_ai(behavior["patterns"])

            cards = []

            for p in behavior["patterns"]:
                cards.append({
                    "file": name,
                    "error_line": p[0],
                    "type": "Behavior Pattern",
                    "cause": p[1],
                    "fix": ai_text,
                    "count": 1,
                    "status": "Active",
                    "severity": "Info"
                })

            results.append({
                "file": name,
                "total_errors": len(cards),
                "analysis": cards
            })

        # Clean temp file
        if os.path.exists(temp):
            os.remove(temp)

    return jsonify({"files": results})
# ---------------- RUN ----------------
if __name__ == "__main__":
    print("UNIFIED ANALYZER STARTED")
    app.run(host="127.0.0.1", port=5000, debug=True,threaded=True)