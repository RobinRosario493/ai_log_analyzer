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
from datetime import datetime
import re
from collections import Counter
import uuid
from concurrent.futures import ThreadPoolExecutor
import threading
KB_LOCK = threading.Lock()

PROVIDER_MAP = {
"9e814aad-3204-11d2-9a82-006008a86939": "Kernel Trace",
"bbccf6c1-6cd1-48c4-80ff-839482e37671": "Windows Defender",
"ef24dd7b-a0c9-4868-bdea-01b759c2dad4": "System Telemetry",
"fc4a40fd-9c01-4f92-b27f-615e1e6e6ff2": "Windows Diagnostics",
}

CURRENT_JOB = {
    "id": None,
    "path": None,
    "results": [],
    "cancelled": False
}

AI_CACHE = {}
KNOWLEDGE_BASE = {}
KB_FILE = "pattern_kb.json"

if os.path.exists(KB_FILE):
    with open(KB_FILE,"r") as f:
        KNOWLEDGE_BASE = json.load(f)
else:
    KNOWLEDGE_BASE = {}

REPORT_ROOT = "analysis_reports"
os.makedirs(REPORT_ROOT, exist_ok=True)
 
app = Flask(__name__, template_folder="templates")
CORS(app)
 
MODEL = "llama3:8b"
OLLAMA_URL = "http://localhost:11434/api/generate"
 
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
PDB_UPLOAD_DIR = "uploaded_pdbs"
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)
 
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB
 


def start_investigation():

    # ✅ If job already active → reuse same folder
    if CURRENT_JOB["id"] and CURRENT_JOB["path"]:
        return CURRENT_JOB["path"]

    # 🔥 Otherwise create new job
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    job_id = f"JOB_{timestamp}_{uuid.uuid4().hex[:6]}"
    job_path = os.path.join(REPORT_ROOT, job_id)

    os.makedirs(job_path, exist_ok=True)

    for folder in ["logs", "dotlogs", "etl", "dumps"]:
        os.makedirs(os.path.join(job_path, folder), exist_ok=True)

    CURRENT_JOB["id"] = job_id
    CURRENT_JOB["path"] = job_path
    CURRENT_JOB["results"] = []
    CURRENT_JOB["cancelled"] = False

    return job_path

# ---------------- AI CALL ----------------
def callai(prompt, timeout=120):

    key = prompt

    # Check cache first
    if key in AI_CACHE:
        print("AI CACHE HIT")
        return AI_CACHE[key]

    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 300
                }
            },
            timeout=timeout
        )

        result = r.json().get("response", "").strip()

        # Store in cache
        AI_CACHE[key] = result

        return result

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

        </style>
    </head>
    <body>

        <h1>File Analysis Report</h1>
        <h2>File: {file_name}</h2>
        <hr>
    """

    if not analysis_cards:
        html += "<p>No issues detected.</p>"

    for card in analysis_cards:

    # --- ETL cards ---
        if "subsystem" in card:

            html += f"""
            <div class="card">

            <b>Type:</b> {card.get("type","")}<br>
            <b>Count:</b> {card.get("count",1)}<br><br>

            <b>Subsystem:</b><br>
            {card.get("subsystem","")}<br><br>

            <b>Observation:</b><br>
            {card.get("observation","")}<br><br>

            <b>Analysis:</b><br>
            {card.get("analysis","")}<br><br>

            <b>Recommended Action:</b><br>
            {card.get("recommended_action","")}

            </div>
            """

        # --- Normal log cards ---
        else:

            html += f"""
            <div class="card">
            <b>Type:</b> {card.get("type","")}<br>
            <b>Occurrences:</b> {card.get("count",1)}<br><br>

            <b>Cause:</b><br>
            {card.get("cause","")}<br><br>

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
# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("rcafinal.html")
 
# ---------------- AI BULK ANALYZE ----------------
def aibulkanalyze(samples):
    if not samples:
        return []

    results = []
    unknown_samples = []
    unknown_indexes = []

    for i, sample in enumerate(samples):

        key = normalize_log(sample)[:150]

        # Check if pattern already known
        if key in KNOWLEDGE_BASE:
            print("KB HIT:", key)
            results.append(KNOWLEDGE_BASE[key])
        else:
            unknown_samples.append(sample)
            unknown_indexes.append(i)
            results.append(None)
    if not unknown_samples:
        return results
    prompt = f"""
You are a senior Windows debugging engineer.
 
For each log event return JSON:
type, cause, fix, severity.
 
Return ONLY JSON array.
 
LOG EVENTS:
{chr(10).join(unknown_samples)}
"""
 
    try:
        
 
        text = callai(prompt, timeout=600)
 
        try:
            ai_results = json.loads(text)
        except:
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1:
                ai_results = json.loads(text[start:end+1])
            else:
                print("AI JSON parse failed:", text)
                return results
        for idx, ai_result in zip(unknown_indexes, ai_results):

            results[idx] = ai_result

            key = normalize_log(samples[idx])[:150]
            with KB_LOCK:
                KNOWLEDGE_BASE[key] = ai_result
        with KB_LOCK:      
            with open(KB_FILE,"w") as f:
                json.dump(KNOWLEDGE_BASE,f)

        return [r if isinstance(r, dict) else {} for r in results]
    except Exception as e:
        print("AI call error:", e)
        return results
 
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

def process_log_file(filepath, filename, job_path):

    with open(filepath, "r", errors="ignore") as f:
        text = f.read()

    result = analyzeerrorsonly(text, filename)

    html_path = os.path.join(
        job_path,
        "logs",
        filename + "_analysis.html"
    )

    save_html_report(
        html_path,
        filename,
        result["analysis"]
    )

    return result
 
# ---------------- CORE LOG ANALYSIS ----------------
def analyzeerrorsonly(logtext, filename):
    lines = logtext.splitlines()
    grouped = defaultdict(list)
    total_errors = 0
 
    for i, line in enumerate(lines):

        if CURRENT_JOB["cancelled"]:
            print("Log analysis cancelled")
            return {"file": filename, "total_errors": 0, "analysis": []}        
        l = line.lower()
 
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
    if CURRENT_JOB["cancelled"]:
        print("Log AI stage cancelled")
        return {"file": filename, "total_errors": 0, "analysis": []}
 
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
           # severity removed
        })
 
    return {
        "file": filename,
        "total_errors": total_errors,
        "analysis": cards
    }
 
# ---------------- LOG ROUTE ----------------
@app.route("/analyze_logs", methods=["POST"])
def analyze_logs():

    job_path = start_investigation()
    files = request.files.getlist("logfile")
    results = []

    saved_files = []

    # Save files first
    for file in files:
        save_path = os.path.join(job_path, "logs", file.filename)
        file.save(save_path)
        saved_files.append((save_path, file.filename))

    with ThreadPoolExecutor(max_workers=min(6, len(saved_files))) as executor:

        futures = []

        for path, name in saved_files:
            futures.append(
                executor.submit(process_log_file, path, name, job_path)
            )

        for future in futures:
            try:
                result = future.result()
                results.append(result)
                CURRENT_JOB["results"].append(result)
            except Exception as e:
                print("Thread error:", e)

    return jsonify({"files": results})

def normalize_log(line):
    line = line.lower()
    line = re.sub(r'\[.*?\]', '', line)
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'[0-9a-fA-F-]{36}', 'GUID', line)
    return line.strip()
def analyze_log_patterns_with_ai(samples):
    results = []
    unknown_samples = []
    unknown_indexes = []

    for i, sample in enumerate(samples):

        key = normalize_log(sample)[:150]

        if key in KNOWLEDGE_BASE:
            print("KB HIT:", key)
            results.append(KNOWLEDGE_BASE[key])
        else:
            unknown_samples.append(sample)
            unknown_indexes.append(i)
            results.append(None)

    # If everything already known
    if not unknown_samples:
        return results
 
    prompt = f"""
    You are a principal-level Windows systems diagnostics engineer working inside an enterprise reliability team.
 
    You specialize in:
    - Windows kernel & drivers
    - Service Control Manager (SCM)
    - Session & token handling
    - Audio subsystem
    - Networking stack
    - Storage & filesystem
    - Security & permissions
    - Process lifecycle
    - Service dependencies
    - ETW & telemetry traces
    - Application runtime failures
 
    You are NOT a chatbot.
    You are a deterministic log-classification engine.
 
    Your job is to analyze system log patterns and produce **precise engineering-grade incident classification**.
 
    For EACH log pattern you MUST:
 
    1. Determine the subsystem involved  
    Examples: audio, network, storage, session manager, service control manager, kernel, driver, authentication, etc.
 
    2. Identify the most probable failure mechanism  
    Examples:
    - permission failure  
    - invalid handle  
    - dependency missing  
    - service startup failure  
    - resource exhaustion  
    - race condition  
    - session mismatch  
    - token impersonation failure  
    - configuration corruption  
 
    3. Infer the root cause using engineering reasoning.
 
    4. Provide a **specific, actionable remediation**  
    Something an engineer can execute immediately.
 
    5. Assign severity based on real operational impact:
 
    - Low → informational / auto-recoverable
    - Medium → degraded service / intermittent failure
    - High → repeated failure / crash / security risk
 
    STRICT RULES:
 
    - NEVER return "Unknown" unless absolutely impossible.
    - NEVER provide generic fixes like "check logs".
    - NEVER repeat the log message as the cause.
    - ALWAYS infer the subsystem.
    - ALWAYS provide a concrete remediation.
    - Be concise but technically precise.
    - Do NOT hallucinate nonexistent components.
 
    Think step-by-step internally like a debugger,  
    but output ONLY the final JSON.
 
    Return ONLY valid JSON array in this exact format:
 
    [
    {{
    "type": "Precise technical failure category",
    "cause": "Specific root cause in engineering terms",
    "fix": "Concrete remediation steps",
    "severity": "Low/Medium/High"
    }}
    ]
 
    LOG PATTERNS:
    {chr(10).join(unknown_samples)}
    """
 
    text = callai(prompt, timeout=300)
 
    # Debug print (keep this for now)
    print("\n========== RAW AI OUTPUT ==========")
    print(text[:800])
    print("===================================\n")
 
    try:
        # Remove markdown fences if model adds them
        text = text.replace("```json", "").replace("```", "").strip()
 
        # ---------- Extract JSON array ----------
        start = text.find("[")
        end = text.rfind("]")
 
        if start != -1 and end != -1 and end > start:
            json_block = text[start:end+1]
            data = json.loads(json_block)
            for idx, ai_result in zip(unknown_indexes, data):

                results[idx] = ai_result

                key = normalize_log(samples[idx])[:150]

                with KB_LOCK:
                    KNOWLEDGE_BASE[key] = ai_result
            with KB_LOCK:
                with open(KB_FILE, "w") as f:
                    json.dump(KNOWLEDGE_BASE, f)

            return results
 
        # ---------- Fallback: single object ----------
        elif text.startswith("{") and text.endswith("}"):
            data = [json.loads(text)]

            for idx, ai_result in zip(unknown_indexes, data):
                results[idx] = ai_result

            return results
 
        else:
            print("AI returned non-JSON format")
            return []
 
        # ---------- Normalize severity ----------
        for item in data:
            if "severity" in item:
                item["severity"] = item["severity"].strip().capitalize()
 
        return data
 
    except Exception as e:
        print("AI JSON parse error:", e)
        print("AI returned:", text[:800])
        return [r if isinstance(r, dict) else {} for r in results]
 
def analyze_dotlog_file(log_text, filename):
 
    lines = log_text.splitlines()
    groups = defaultdict(list)
 
    # STEP 1: GROUP
    for i, line in enumerate(lines):
        if CURRENT_JOB["cancelled"]:
            print(".log grouping cancelled")
            return {"file": filename, "total_errors": 0, "analysis": []}

        key = normalize_log(line)[:200]
        groups[key].append((i, line))
 
    # STEP 2: PREPARE SAMPLES
    samples = []
    keys = []

    for key, occ in groups.items():
        samples.append(occ[0][1])
        keys.append(key)
    # ADD THIS
    index_map = {k:i for i,k in enumerate(keys)}
    # STEP 3: AI CALL
    ai_results = []
    batch = 6
 
    for i in range(0, len(samples), batch):
        if CURRENT_JOB["cancelled"]:
            print(".log AI cancelled")
            return {"file": filename, "total_errors": 0, "analysis": []}
        chunk = samples[i:i+batch]
        res = analyze_log_patterns_with_ai(chunk)
        ai_results.extend(res)
 
    # STEP 4: BUILD CARDS
    cards = []

    for key, occ in groups.items():

        if CURRENT_JOB["cancelled"]:
            print(".log card building cancelled")
            return {"file": filename, "total_errors": 0, "analysis": []}

        idx = index_map.get(key)
        if idx is None:
            continue

        count = len(occ)
        sample = occ[0][1]

        if idx < len(ai_results):

            r = ai_results[idx]

            if not isinstance(r, dict):
                r = {}

            severity = r.get("severity", "Low")

            if severity == "Low":
                continue

            cards.append({
                "file": filename,
                "error_line": sample,
                "type": r.get("type","Unknown"),
                "cause": r.get("cause","Unknown"),
                "fix": r.get("fix","Check manually"),
                "count": count,
                "status": "Active",
                "severity": severity
            })
 
    return {
        "file": filename,
        "total_errors": sum(len(v) for v in groups.values()),
        "analysis": cards
    }

def process_dotlog_file(filepath, filename, job_path):

    with open(filepath, "r", errors="ignore") as f:
        text = f.read()

    result = analyze_dotlog_file(text, filename)

    html_path = os.path.join(
        job_path,
        "dotlogs",
        filename + "_analysis.html"
    )

    save_html_report(
        html_path,
        filename,
        result["analysis"]
    )

    return result

@app.route("/analyze_dotlogs", methods=["POST"])
def analyze_dotlogs():

    job_path = start_investigation()
    files = request.files.getlist("logfile")
    results = []

    saved_files = []

    for file in files:
        save_path = os.path.join(job_path, "dotlogs", file.filename)
        file.save(save_path)
        saved_files.append((save_path, file.filename))

    with ThreadPoolExecutor(max_workers=min(4, len(saved_files))) as executor:

        futures = []

        for path, name in saved_files:
            futures.append(
                executor.submit(process_dotlog_file, path, name, job_path)
            )

        for future in futures:
            try:
                result = future.result()
                results.append(result)
                CURRENT_JOB["results"].append(result)
            except Exception as e:
                print("Thread error:", e)

    return jsonify({"files": results})
# ---------------- WINDBG ----------------
def runwindbg(dumppath, pdbpath=None):
    logfile = dumppath + "_windbg.txt"

    cmd = [WINDBG, "-z", dumppath]

    if pdbpath:
        cmd += ["-y", PDB_UPLOAD_DIR]

    cmd += ["-logo", logfile, "-c", "!analyze -v; lm; k; q"]

    try:
        subprocess.run(cmd, timeout=300)
    except Exception as e:
        print("WinDbg error:", e)
        return ""

    if os.path.exists(logfile):
        with open(logfile, "r", errors="ignore") as f:
            return f.read()

    return ""
 
def analyzedumpai(text):
    prompt = f"""
You are a senior Windows kernel crash dump analyst.

You are given WinDbg !analyze -v output.

Think like a real Windows debugging engineer.

You MUST:
- Infer subsystem from driver/module.
- If breakpoint (0x80000003), classify as application assertion.
- If driver missing, infer from IMAGE_NAME or MODULE_NAME.
- Always provide a concrete technical fix.
- Root cause MUST NOT be empty.

Return ONLY valid JSON.
No markdown. No explanation outside JSON.

Return EXACTLY this structure:

{{
  "bugcheck": "",
  "faulting_driver": "",
  "subsystem": "",
  "root_cause": "",
  "fix": ""
}}

WinDbg Output:
{text[:8000]}
"""
    return callai(prompt, timeout=300)
 
def process_dump_file(dump_path, dump_name, pdb_path, job_path):

    windbg_output = runwindbg(dump_path, pdb_path)

    if not windbg_output:
        root_cause = "WinDbg failed to produce output."
        fix = "Verify dump file integrity and debugger installation."
        bugcheck = ""
        driver = ""
        subsystem = ""

    else:

        ai_text = analyzedumpai(windbg_output)

        clean_text = ai_text.replace("```json", "").replace("```", "").strip()

        start = clean_text.find("{")
        end = clean_text.rfind("}")

        bugcheck = ""
        driver = ""
        subsystem = ""
        root_cause = ""
        fix = ""

        if start != -1 and end != -1 and end > start:
            json_block = clean_text[start:end+1]

            try:
                data = json.loads(json_block)

                bugcheck = data.get("bugcheck", "")
                driver = data.get("faulting_driver", "")
                subsystem = data.get("subsystem", "")
                root_cause = data.get("root_cause", "")
                fix = data.get("fix", "")

            except:
                root_cause = clean_text
                fix = "Manual review required."

    formatted_cause = (
        f"Bugcheck: {bugcheck or 'Unknown'}\n"
        f"Faulting Driver: {driver or 'Unknown'}\n"
        f"Subsystem: {subsystem or 'Unknown'}\n\n"
        f"Detailed Analysis:\n{root_cause}"
    )

    dump_result = {
        "file": dump_name,
        "analysis": [{
            "type": "Crash Dump",
            "cause": formatted_cause,
            "fix": fix,
            "count": 1,
            "severity": "High"
        }]
    }

    html_path = os.path.join(
        job_path,
        "dumps",
        dump_name + "_analysis.html"
    )

    save_html_report(
        html_path,
        dump_name,
        dump_result["analysis"]
    )

    return dump_result
# ---------------- DUMP ROUTE ----------------
@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    job_path = start_investigation()

    dumpfiles = request.files.getlist("dumpfile")
    pdbfiles = request.files.getlist("pdbfile")

    results = []
    saved_dumps = []

    for i, dump in enumerate(dumpfiles):

        dump_path = os.path.join(job_path, "dumps", dump.filename)
        dump.save(dump_path)

        pdb_path = None

        if i < len(pdbfiles):
            pdb = pdbfiles[i]

            if pdb.filename.endswith(".pdb"):
                pdb_path = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdb_path)

        saved_dumps.append((dump_path, dump.filename, pdb_path))

    with ThreadPoolExecutor(max_workers=min(4, len(saved_dumps))) as executor:

        futures = []

        for path, name, pdb in saved_dumps:
            futures.append(
                executor.submit(process_dump_file, path, name, pdb, job_path)
            )

        for future in futures:
            try:
                result = future.result()
                results.append(result)
                CURRENT_JOB["results"].append(result)
            except Exception as e:
                print("Thread error:", e)

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
 
    summary = str(CURRENT_JOB["results"])[-3000:] 
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
 
def convert_etl_to_text(etl_path):

    out_csv = etl_path + "_decoded.csv"

    cmd = [
        "tracerpt",
        etl_path,
        "-o",
        out_csv,
        "-of",
        "CSV",
        "-y"
    ]

    try:
        subprocess.run(cmd, timeout=900)
    except Exception as e:
        print("ETL decode error:", e)
        return ""

    if os.path.exists(out_csv):
        with open(out_csv, "r", errors="ignore") as f:
            return f.read()

    return ""
 
def get_etl_summary(etl_path):

    summary_file = etl_path + "_summary.txt"

    cmd = [
        "tracerpt",
        etl_path,
        "-summary",
        summary_file
    ]

    subprocess.run(cmd, timeout=300)

    if os.path.exists(summary_file):
        with open(summary_file, "r", errors="ignore") as f:
            return f.read()

    return ""
 
def analyze_etl_behavior(csv_text, filename):

    reader = csv.DictReader(StringIO(csv_text))
    rows = list(reader)
    rows.sort(key=lambda r: r.get("TimeCreated",""))

    if not rows:
        return {"file": filename, "patterns": []}

    patterns = []
    provider_counts = defaultdict(int)
    error_counts = defaultdict(int)

    timestamps = []
    services = set()

    for r in rows:

        provider = (r.get("ProviderName") or "Unknown").lower()
        subsystem = PROVIDER_MAP.get(provider, provider)

        msg = (r.get("Message") or "").lower()
        level = (r.get("LevelDisplayName") or "").lower()

        provider_counts[subsystem] += 1

        if level in ["error","critical"]:
            error_counts[subsystem] += 1

        if "service" in msg:
            services.add(subsystem)

        # timestamps
        t = r.get("TimeCreated")
        if t:
            try:
                timestamps.append(datetime.fromisoformat(t))
            except:
                pass

        # --- Failure patterns ---
        if "access denied" in msg:
            patterns.append(("Permission Failure", msg))

        if "timeout" in msg:
            patterns.append(("Timeout Condition", msg))

        if "retry" in msg:
            patterns.append(("Retry Loop", msg))

        if "failed" in msg:
            patterns.append(("Operation Failure", msg))

        if "crash" in msg or "bugcheck" in msg:
            patterns.append(("Crash Indicator", msg))

    # --- Event storm detection ---
    for provider, count in provider_counts.items():

        if count > 1000:

            patterns.append((
                "Event Storm",
                f"{provider} emitted {count} events"
            ))

    # --- High activity providers ---
    for provider, count in provider_counts.items():

        if count > 200:

            patterns.append((
                "High Frequency ETW Activity",
                f"{provider} generated {count} events"
            ))

    # --- Error-heavy providers ---
    for provider, count in error_counts.items():

        if count > 10:

            patterns.append((
                "Repeated Failure Pattern",
                f"{provider} produced {count} error events"
            ))

    # --- Time gap detection ---
    if len(timestamps) > 5:

        gaps = [
            (timestamps[i] - timestamps[i-1]).total_seconds()
            for i in range(1, len(timestamps))
        ]

        if max(gaps) > 120:

            patterns.append((
                "Execution Stall Detected",
                f"Max ETW gap {max(gaps)} seconds"
            ))

    if not patterns:
        patterns.append(("Normal ETW Execution", "No abnormal patterns detected"))

    patterns = list(set(patterns))
    patterns = patterns[:12]

    return {
        "file": filename,
        "patterns": patterns
    }
 
def analyze_etl_with_ai(patterns, summary_text):

    samples = [p[0] + " : " + p[1] for p in patterns]

    prompt = f"""
You are a senior Windows diagnostics engineer.

You are analyzing decoded ETW (Event Tracing for Windows) telemetry.

Your job is to produce an engineering-style analysis similar to what a
Windows reliability engineer would write during root cause investigation.

Explain the behavior of the ETW trace using these sections:

Subsystem:
Identify the Windows subsystem or service involved.

Observation:
Describe what the ETW trace shows.

Analysis:
Explain what the behavior means technically.

Root Cause:
Determine the most probable cause.

Recommended Action:
Provide concrete remediation or state that no action is required.
Return ONLY JSON in this format:

{{
"subsystem": "",
"observation": "",
"analysis": "",
"recommended_action": ""
}}

Important rules:
• Only infer what the trace evidence supports
• Do NOT hallucinate hardware failures
• If behavior is normal, clearly state that
• Write like a professional diagnostics report

ETW Summary Information:
{summary_text[:3000]}

Detected Behavioral Patterns:
{patterns}
"""

    return callai(prompt, timeout=180)

def process_etl_file(filepath, filename, job_path):

    csv_text = convert_etl_to_text(filepath)
    summary_text = get_etl_summary(filepath)

    if not csv_text:
        result = {
            "file": filename,
            "total_errors": 0,
            "analysis": []
        }

    else:

        behavior = analyze_etl_behavior(csv_text, filename)

        if not behavior["patterns"]:
            behavior["patterns"] = [
                ("Normal behavior detected", "No anomalies found")
            ]

        ai_text = analyze_etl_with_ai(
            behavior["patterns"],
            summary_text
        )

        # ---- Parse AI JSON ----
        try:

            clean = ai_text.replace("```json","").replace("```","").strip()

            start = clean.find("{")
            end = clean.rfind("}")

            data = {}

            if start != -1 and end != -1:
                json_block = clean[start:end+1]
                data = json.loads(json_block)

        except:
            data = {}

        # ---- Build ETL card ----
        cards = []

        cards.append({
            "file": filename,
            "type": "ETW Trace Analysis",

            "subsystem": data.get("subsystem","Unknown subsystem"),
            "observation": data.get("observation","No observation available"),
            "analysis": data.get("analysis","No analysis available"),
            "recommended_action": data.get("recommended_action","No action required"),

            # 👇 ADD THESE FOR UI COMPATIBILITY
            "error_line": data.get("observation","No observation available"),
            "cause": data.get("analysis","No analysis available"),
            "fix": data.get("recommended_action","No action required"),

            "count": 1,
            "status": "Resolved"
        })
        result = {
            "file": filename,
            "total_errors": len(cards),
            "analysis": cards
        }

    html_path = os.path.join(
        job_path,
        "etl",
        filename + "_analysis.html"
    )

    save_html_report(
        html_path,
        filename,
        result["analysis"]
    )

    return result

@app.route("/analyze_etl", methods=["POST"])
def analyze_etl():

    job_path = start_investigation()
    files = request.files.getlist("etlfile")
    results = []

    saved_files = []

    for file in files:
        save_path = os.path.join(job_path, "etl", file.filename)
        file.save(save_path)
        saved_files.append((save_path, file.filename))

    with ThreadPoolExecutor(max_workers=min(4, len(saved_files))) as executor:

        futures = []

        for path, name in saved_files:
            futures.append(
                executor.submit(process_etl_file, path, name, job_path)
            )

        for future in futures:
            try:
                result = future.result()
                results.append(result)
                CURRENT_JOB["results"].append(result)
            except Exception as e:
                print("Thread error:", e)

    return jsonify({"files": results})

def preprocess_for_correlation(all_results):

    weighted = []

    for file in all_results:
        for card in file.get("analysis", []):

            if not isinstance(card, dict):
                continue

            cause = card.get("type")
            fix = card.get("fix")
            count = card.get("count", 1)

            for _ in range(count):
                weighted.append((cause, fix))

    if not weighted:
        return []

    counter = Counter(weighted)

    return counter.most_common(3)

def ai_global_correlation(top_candidates):

    if not top_candidates:
        return {
            "root_cause": "No correlated patterns found",
            "fix": "Insufficient data for correlation",
            "confidence": "Low"
        }

    summary = "\n".join([
    f"Failure Pattern: {c[0][0]} | Occurrences Score: {c[1]}"
        for c in top_candidates
    ])

    prompt = f"""
        You are an enterprise reliability engineer performing incident correlation.

        You will receive the most frequent failure patterns across logs, dumps, and ETL traces.

Your task:
Determine the SINGLE most probable root cause.

Rules:
- Return EXACTLY one JSON object.
- Do NOT add explanation.
- Do NOT add markdown.
- Do NOT add text before or after JSON.
- Always return JSON even if uncertain.

Patterns:
{summary}

JSON format:

{{
"root_cause": "Most probable underlying issue",
"fix": "Concrete remediation steps",
"confidence": "High | Medium | Low"
}}
"""

    text = callai(prompt, timeout=180)

    print("\n====== CORRELATION RAW AI OUTPUT ======")
    print(text)
    print("=======================================\n")

    if not text:
        return {
            "root_cause": "AI returned empty response",
            "fix": "Check Ollama service",
            "confidence": "Low"
        }

    try:
        # Remove markdown if present
        text = text.replace("```json", "").replace("```", "").strip()

        match = re.search(r'\{.*?\}', text, re.DOTALL)

        if match:
            json_block = match.group(0)
            return json.loads(json_block)
        else:
            raise ValueError("No JSON found")

    except Exception as e:
        print("Correlation JSON parse error:", e)
        print("AI output was:", text)

        return {
            "root_cause": "Correlation parsing failed",
            "fix": "Manual review required",
            "confidence": "Low"
        }



def save_rca(job_path, rca_data):

    # Save JSON
    with open(os.path.join(job_path, "rca.json"), "w") as f:
        json.dump(rca_data, f, indent=2)

    # Save HTML
    html = f"""
    <html>
    <head>
        <title>Final RCA Report</title>
        <style>
            body {{ font-family: Arial; background:#0f172a; color:white; padding:30px; }}
            .card {{ background:#1e293b; padding:20px; border-radius:10px; }}
        </style>
    </head>
    <body>
        <h1>Root Cause Analysis</h1>
        <div class="card">
            <h2>Root Cause</h2>
            <p>{rca_data.get("root_cause")}</p>

            <h2>Fix</h2>
            <p>{rca_data.get("fix")}</p>

            <h2>Confidence</h2>
            <p>{rca_data.get("confidence")}</p>
        </div>
    </body>
    </html>
    """

    with open(os.path.join(job_path, "rca_report.html"), "w") as f:
        f.write(html)

@app.route("/final_correlation", methods=["GET"])
def final_correlation():

    if not CURRENT_JOB["results"]:
        return jsonify({"message": "No files analyzed yet."})

    top = preprocess_for_correlation(CURRENT_JOB["results"])
    print("TOP CORRELATION INPUT:", top)

    if not top:
        return jsonify({"message": "No significant patterns found."})

    final = ai_global_correlation(top)

    save_rca(CURRENT_JOB["path"], final)

    # 🔥 AUTO CLOSE CURRENT JOB AFTER CORRELATION
    CURRENT_JOB["id"] = None
    CURRENT_JOB["path"] = None
    CURRENT_JOB["results"] = []
    CURRENT_JOB["cancelled"] = False

    return jsonify({
        "global_summary": final
    })


def start_job():
    CURRENT_JOB["id"] = str(uuid.uuid4())
    CURRENT_JOB["cancelled"] = False
    return CURRENT_JOB["id"]
@app.route("/cancel_analysis")
def cancel_analysis():
    CURRENT_JOB["cancelled"] = True
    return jsonify({"status": "cancelled"})
@app.route("/load_session")
def load_session():
    return jsonify({
        "files": CURRENT_JOB["results"]
    })

# ---------------- RUN ----------------
if __name__ == "__main__":
    print("UNIFIED ANALYZER STARTED")
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)