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
 
app = Flask(__name__, template_folder="code")
CORS(app)
 
MODEL = "llama3.1:8b"
OLLAMA_URL = "http://localhost:11434/api/generate"
 
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
PDB_UPLOAD_DIR = "uploaded_pdbs"
os.makedirs(PDB_UPLOAD_DIR, exist_ok=True)
 
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  * 1024 * 1024
 
def extract_timestamp(line):

    patterns = [
        r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",  # Event Viewer
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        r"\d{2}:\d{2}:\d{2}",
    ]

    for p in patterns:
        m = re.search(p, line)
        if m:
            return m.group(0)

    return None
def extract_event_sources(text):
    events = parse_eventviewer_txt(text)
    sources = set()
    for e in events:
        src = e.get("source")
        if src:
            sources.add(src)
    return sorted(list(sources))

def build_timeline(all_results):
    timeline = []
    for file in all_results:
        fname = file.get("file")
        for card in file.get("analysis", []):
            line = card.get("error_line", "")
            timestamp = extract_timestamp(line)
            event = {
                "timestamp": timestamp,
                "file": fname,
                "type": card.get("type"),
                "cause": card.get("cause")
            }
            timeline.append(event)
    return timeline

def sort_timeline(events):

    def parse_time(t):

        try:
            return datetime.strptime(t,"%Y-%m-%d %H:%M:%S")
        except:
            try:
                return datetime.strptime(t,"%H:%M:%S")
            except:
                return datetime.max

    events.sort(key=lambda x: parse_time(x["timestamp"]) if x["timestamp"] else datetime.max)

    return events

@app.route("/timeline", methods=["GET"])
def generate_timeline():

    if not CURRENT_JOB["results"]:
        return jsonify({"message": "No analysis results available"})

    # use existing functions
    events = build_timeline(CURRENT_JOB["results"])
    events = sort_timeline(events)

    save_timeline_report(CURRENT_JOB["path"], events)

    return jsonify({
        "timeline_events": events,
        "report": "timeline_report.html generated"
    })


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

def save_timeline_report(job_path, timeline_events):

    html = """
    <html>
    <head>
        <title>Timeline Reconstruction</title>
    </head>
    <body>

    <h1>Incident Timeline Reconstruction</h1>
    <hr>
    """

    for e in timeline_events:

        html += f"""
        <div>
            <b>{e.get("timestamp","Unknown")}</b><br>
            File: {e.get("file","")}<br>
            Type: {e.get("type","")}<br>
            Cause: {e.get("cause","")}
            <hr>
        </div>
        """

    html += "</body></html>"

    path = os.path.join(job_path, "timeline_report.html")

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
        
# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("eventviewer1.html")
 
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
You are a principal-level Windows systems reliability engineer working in an enterprise diagnostics team.

You specialize in:

- Windows kernel behavior
- Service Control Manager (SCM)
- Windows Event Viewer diagnostics
- Driver and subsystem failures
- Authentication & security
- Networking stack
- Storage & filesystem
- Process lifecycle
- Application runtime failures
- Windows update & component servicing
- ETW telemetry interpretation

You are NOT a chatbot.

You are a deterministic Windows incident classification engine.

Your job is to analyze Windows Event Viewer events and produce **engineering-grade failure classification**.

Each input represents a **Windows Event pattern** such as:

Source + EventID + sample message.

For EACH event pattern you MUST:

1. Identify the **Windows subsystem involved**

Examples:
- Service Control Manager
- Kernel Power
- Application Runtime
- Networking stack
- Storage subsystem
- Security subsystem
- Windows Update
- Driver subsystem

2. Identify the **failure mechanism**

Examples:
- service startup failure
- dependency missing
- application crash
- kernel power restart
- driver failure
- permission error
- configuration corruption
- resource exhaustion

3. Infer the **root cause using engineering reasoning**.

4. Provide a **specific actionable remediation** that a system administrator can perform.

5. Assign severity based on operational impact:

Low → informational / expected behavior  
Medium → degraded service / intermittent failure  
High → crash / restart / persistent service failure

STRICT RULES:

- NEVER return "Unknown" unless absolutely impossible
- NEVER repeat the log message as the cause
- NEVER give vague fixes like "check logs"
- ALWAYS infer subsystem
- ALWAYS provide concrete remediation
- Be concise but technically precise
- Do NOT hallucinate nonexistent components

Think internally like a Windows debugger,  
but output ONLY the final JSON.

Return ONLY a JSON array in this exact format:

[
{{
"type": "Precise failure classification",
"cause": "Technical root cause explanation",
"fix": "Concrete remediation steps",
"severity": "Low/Medium/High"
}}
]

EVENT PATTERNS:
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

def parse_eventviewer_txt(text):

    events = []

    lines = text.splitlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("level"):
            continue

        # split using tab or multiple spaces
        parts = re.split(r'\t+|\s{2,}', line)

        if len(parts) < 4:
            continue

        level = parts[0]

        datetime_field = parts[1]

        # split date and time
        dt_parts = datetime_field.split()

        if len(dt_parts) >= 2:
            date = dt_parts[0]
            time = dt_parts[1]
        else:
            date = ""
            time = ""

        source = parts[2]

        eventid = parts[3]

        events.append({
            "level": level,
            "date": date,
            "time": time,
            "source": source,
            "eventid": eventid
        })

    return events
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

def auto_generate_timeline():

    if not CURRENT_JOB["results"]:
        return

    try:
        events = build_timeline(CURRENT_JOB["results"])
        events = sort_timeline(events)
        save_timeline_report(CURRENT_JOB["path"], events)
        print("Timeline updated")
    except Exception as e:
        print("Timeline generation error:", e)
 
def getcontext(lines, index, window=3):
    start = max(0, index - window)
    end = min(len(lines), index + window + 1)
    return " ".join(lines[start:end])

def process_log_file(filepath, filename, job_path, sources):

    with open(filepath, "r", errors="ignore") as f:
        text = f.read()

    result = analyzeerrorsonly(text, filename, sources)

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
def analyzeerrorsonly(logtext, filename, selected_sources=None):

    events = parse_eventviewer_txt(logtext)

    grouped = defaultdict(list)

    for e in events:

        source = e.get("source")
        eventid = e.get("eventid")
        date = e.get("date")
        time = e.get("time")

        # FILTER BY SOURCE
        if selected_sources and source not in selected_sources:
            continue

        line = f"{date} {time} {source} EventID {eventid}"

        key = f"{source}_{eventid}"

        grouped[key].append(line)

    if not grouped:
        return {"file": filename, "total_errors": 0, "analysis": []}

    samples = []
    keys = []

    for key, rows in grouped.items():
        samples.append(rows[0])
        keys.append(key)

    airesults = aibulkanalyze(samples)

    cards = []

    for key, rows in grouped.items():

        sample = rows[0]
        count = len(rows)

        r = {}

        if keys.index(key) < len(airesults):
            r = airesults[keys.index(key)] or {}

        cards.append({
            "file": filename,
            "error_line": sample,
            "type": r.get("type", "Event Pattern"),
            "cause": r.get("cause", "Repeated Windows event detected"),
            "fix": r.get("fix", "Investigate event source"),
            "count": count,
            "status": "Active"
        })

    return {
        "file": filename,
        "total_errors": sum(len(v) for v in grouped.values()),
        "analysis": cards
    }
# ---------------- LOG ROUTE ----------------
@app.route("/analyze_logs", methods=["POST"])
def analyze_logs():

    job_path = start_investigation()

    files = request.files.getlist("logfile")
    sources = request.form.getlist("sources")

    results = []
    saved_files = []

    for file in files:

        save_path = os.path.join(job_path, "logs", file.filename)
        file.save(save_path)

        saved_files.append((save_path, file.filename))

    with ThreadPoolExecutor(max_workers=min(6, len(saved_files))) as executor:

        futures = []

        for path, name in saved_files:

            futures.append(
                executor.submit(process_log_file, path, name, job_path, sources)
            )

        for future in futures:

            try:
                result = future.result()
                results.append(result)
                CURRENT_JOB["results"].append(result)

            except Exception as e:
                print("Thread error:", e)

    # --- AUTO GENERATE TIMELINE ---
    try:
        events = build_timeline(CURRENT_JOB["results"])
        events = sort_timeline(events)
        save_timeline_report(CURRENT_JOB["path"], events)
    except Exception as e:
        print("Timeline generation error:", e)
    auto_generate_timeline()
    return jsonify({"files": results})


@app.route("/get_event_sources", methods=["POST"])
def get_event_sources():

    file = request.files.get("logfile")

    if not file:
        return jsonify({"sources": []})

    text = file.read().decode(errors="ignore")

    sources = extract_event_sources(text)

    return jsonify({"sources": sources})

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
 
 CONTEXT-AWARE ANALYSIS RULES:

Each log sample contains surrounding context.

You MUST:

1. Determine error lifecycle:
   - Active → still failing, no recovery
   - Resolved → recovered after failure
   - Intermittent → fails and recovers repeatedly

2. Identify causal chain:
   - What event triggered this failure?
   - Look at previous lines in context

3. Detect resolution signals:
   Examples:
   - "started successfully"
   - "connected"
   - "retry succeeded"
   - "initialized"
   - "recovered"

4. Adjust severity:
   - Resolved → reduce severity
   - Active + repeated → increase severity

5. Return a new field:
   "status": "Active | Resolved | Intermittent"
    Return ONLY valid JSON array in this exact format:
 
    [
    {{
    "type": "Precise technical failure category",
    "cause": "Specific root cause in engineering terms",
    "fix": "Concrete remediation steps",
    "severity": "Low/Medium/High"
    "status": "Active | Resolved | Intermittent"
    }}
    ]
 
    LOG PATTERNS:
    {chr(10).join(unknown_samples)}
    """
 
    text = callai(prompt, timeout=600)
 
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

        # ✅ ONLY process ERROR logs
        if "error" not in line.lower():
            continue

        # ✅ Extract signature from error only
        signature = extractsignature(line)

        # ✅ Include context (important for resolution detection)
        context = getcontext(lines, i, window=3)

        key = normalize_log(signature)[:200]

        groups[key].append({
            "index": i,
            "error": line,
            "context": context
        })
 
    # STEP 2: PREPARE SAMPLES
    samples = []
    keys = []

    for key, occ in groups.items():
        idx = occ[0]["index"]
        context = getcontext(lines, idx, window=5)
        samples.append(context)
        keys.append(key)
    # ADD THIS
    index_map = {k:i for i,k in enumerate(keys)}
    # STEP 3: AI CALL
    ai_results = []
    batch = 2
 
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
        sample = occ[0]["error"]

        if idx < len(ai_results):

            r = ai_results[idx]

            if not isinstance(r, dict):
                r = {}

            severity = r.get("severity", "Low")

            if severity == "Low"and r.get("status") == "Resolved":
                continue

            cards.append({
                "file": filename,
                "error_line": sample,
                "type": r.get("type","Unknown"),
                "cause": r.get("cause","Unknown"),
                "fix": r.get("fix","Check manually"),
                "count": count,
                "status": r.get("status", "Active"),
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
    auto_generate_timeline()
    return jsonify({"files": results})

def extract_driver_from_windbg(text):

    # 1. IMAGE_NAME
    m = re.search(r"IMAGE_NAME:\s+(\S+)", text)
    if m:
        return m.group(1)

    # 2. MODULE_NAME
    m = re.search(r"MODULE_NAME:\s+(\S+)", text)
    if m:
        return m.group(1)

    # 3. Probably caused by
    m = re.search(r"Probably caused by:\s+(\S+)", text)
    if m:
        return m.group(1)

    return None
# ---------------- WINDBG ----------------
def runwindbg(dumppath, pdbpath=None, job_path=None, dump_name=None):
    if job_path and dump_name:
        logfile = os.path.join(job_path, "dumps", dump_name + "_windbg.txt")
    else:
        logfile = dumppath + "_windbg.txt"
    symbol_cmd = ".symfix; .reload;"

    if pdbpath:
        symbol_cmd = f'.symfix; .sympath+ "{PDB_UPLOAD_DIR}"; .reload; '

    cmd = [
        WINDBG,
        "-z", dumppath,
        "-y", f"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;{PDB_UPLOAD_DIR}",
        "-logo", logfile,
        "-c", f"{symbol_cmd}!analyze -v; lm; k; q"
    ]

    try:
        subprocess.run(cmd, timeout=1200)
    except Exception as e:
        print("WinDbg error:", e)
        return ""

    if os.path.exists(logfile):
        with open(logfile, "r", errors="ignore") as f:
            return f.read()

    return ""

AI_LOCK = threading.Lock()

def analyzedumpai(text):
    with AI_LOCK:   # 🔥 ensures only ONE AI call at a time
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
    {text[:6000]}
    """
        return callai(prompt, timeout=600)


def extract_fault_location(text):
    module = None
    offset = None
    instruction = None

    # 1. Try SYMBOL_NAME first (most reliable)
    m = re.search(r"SYMBOL_NAME:\s+([^\+]+)\+([0-9a-fA-Fx]+)", text)
    if m:
        module = m.group(1).strip()
        offset = m.group(2).replace("0x", "")

    # 2. Fallback to IMAGE_NAME + offset
    if not module:
        m = re.search(r"IMAGE_NAME:\s+(\S+)", text)
        if m:
            module = m.group(1)

    # 3. Extract from IP line (HotkeyServiceUWP+0xeb138)
    if not offset:
        m = re.search(r"(\S+)\+0x([0-9a-fA-F]+)", text)
        if m:
            module = module or m.group(1)
            offset = m.group(2)

    # 4. Extract instruction (from disassembly line)
    inst = re.search(r"\n[0-9a-fA-F`]+\s+([a-zA-Z]+\s+.*)", text)
    if inst:
        instruction = inst.group(1).strip()

    return module, offset, instruction
 
def process_dump_file(dump_path, dump_name, pdb_path, job_path):
    formatted_cause = "Crash analysis unavailable."

    windbg_output = runwindbg(dump_path, pdb_path, job_path, dump_name)

    if not windbg_output:
        root_cause = "WinDbg failed to produce output."
        fix = "Verify dump file integrity and debugger installation."
        bugcheck = ""
        driver = ""
        subsystem = ""

        formatted_cause = (
            "Bugcheck: Unknown\n"
            "Faulting Driver: Unknown\n"
            "Subsystem: Unknown\n\n"
            f"Detailed Analysis:\n{root_cause}"
        )

    else:
        # ✅ Extract location EARLY
        module, offset, instruction = extract_fault_location(windbg_output)

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
                detected_driver = extract_driver_from_windbg(windbg_output)
                ai_driver = data.get("faulting_driver", "")

                driver = detected_driver or ai_driver or module or "Unknown"
                subsystem = data.get("subsystem", "")
                root_cause = data.get("root_cause", "")
                fix = data.get("fix", "")

            except:
                root_cause = clean_text
                fix = "Manual review required."

        if not driver or driver.lower() == "unknown":
            driver = "Unknown (Likely memory corruption or indirect driver failure)"

        # ✅ Build location info properly
        location_info = driver

        if module and offset:
            location_info = f"{module}+0x{offset}"

        if instruction:
            location_info += f" ({instruction})"

        # ✅ Always build output
        formatted_cause = (
            f"Bugcheck: {bugcheck or 'Unknown'}\n"
            f"Faulting Location: {location_info}\n"
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

    html_path = os.path.join(job_path, "dumps", dump_name + "_analysis.html")

    save_html_report(html_path, dump_name, dump_result["analysis"])

    return dump_result
# ---------------- DUMP ROUTE ----------------
@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    job_path = start_investigation()

    # ✅ CASE 1: Path-based
    if request.is_json:
        data = request.get_json()
        dump_path = data.get("dump_path")
        if dump_path:
            dump_path = dump_path.strip().strip('"')
        print("DEBUG PATH:", dump_path)

        if not dump_path:
            return jsonify({"error": "No path received"}), 400

        if not os.path.exists(dump_path):
            return jsonify({"error": f"File not found: {dump_path}"}), 400

        # ✅ NOW ACTUALLY CALL ANALYSIS
        result = process_dump_file(
            dump_path,
            os.path.basename(dump_path),
            None,
            job_path
        )

        CURRENT_JOB["results"].append(result)
        return jsonify({"files": [result]})

    # ✅ CASE 2: Upload-based
    dumpfiles = request.files.getlist("dumpfile")
    pdbfiles = request.files.getlist("pdbfile")

    print("Files received:", dumpfiles)

    if not dumpfiles:
        return jsonify({"error": "No dump files received"}), 400

    

    if not dumpfiles:
        return jsonify({"error": "No dump files received"}), 400

    dump_dir = os.path.join(job_path, "dumps")
    os.makedirs(dump_dir, exist_ok=True)

    results = []
    saved_dumps = []

    for i, dump in enumerate(dumpfiles):

        if not dump.filename.endswith(".dmp"):
            print("Skipping non-dump:", dump.filename)
            continue

        dump_path = os.path.join(dump_dir, dump.filename)
        print("Saving dump to:", dump_path)

        # ✅ Stream save (important for large files)
        with open(dump_path, "wb") as f:
            while True:
                chunk = dump.stream.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)

        pdb_path = None

        if i < len(pdbfiles):
            pdb = pdbfiles[i]
            if pdb.filename.endswith(".pdb"):
                pdb_path = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdb_path)

        saved_dumps.append((dump_path, dump.filename, pdb_path))

    with ThreadPoolExecutor(max_workers=1) as executor:

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

    if not results:
        return jsonify({"error": "Analysis failed"}), 500

    auto_generate_timeline()

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
    auto_generate_timeline()
    return jsonify({"files": results})

def preprocess_for_correlation(all_results):

    patterns = []

    for file in all_results:
        fname = file.get("file")

        for card in file.get("analysis", []):

            if not isinstance(card, dict):
                continue

            patterns.append({
                "type": card.get("type"),
                "fix": card.get("fix"),
                "severity": card.get("severity", "Low"),
                "file": fname
            })

    return patterns

    counter = Counter(weighted)

    return counter.most_common(3)

def build_correlation_candidates(patterns):

    grouped = defaultdict(list)

    for p in patterns:
        key = p["type"]
        grouped[key].append(p)

    scored = []

    for key, items in grouped.items():

        score = 0
        sources = set()
        fixes = set()

        for item in items:

            severity = item.get("severity", "Low")

            weight = (
                3 if severity == "High" else
                2 if severity == "Medium" else
                1
            )

            score += weight
            sources.add(item.get("file"))
            fixes.add(item.get("fix"))

        scored.append({
            "type": key,
            "score": score,
            "source_count": len(sources),
            "fixes": list(fixes)
        })

    # Sort by:
    # 1. score
    # 2. number of sources (cross-correlation)
    scored.sort(key=lambda x: (x["score"], x["source_count"]), reverse=True)

    return scored
def smart_correlation(candidates):

    if not candidates:
        return {
            "root_cause": "No significant patterns found",
            "fix": "Insufficient data",
            "confidence": "Low"
        }

    top = candidates[0]

    # Detect conflict
    if len(candidates) > 1:
        second = candidates[1]

        # If top two are close → conflict
        if abs(top["score"] - second["score"]) <= 2:
            return {
                "root_cause": "Multiple competing failure patterns detected",
                "fix": "Investigate top subsystems separately",
                "confidence": "Low"
            }

    # Determine confidence
    if top["source_count"] >= 2:
        confidence = "High"
    elif top["score"] >= 5:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Choose best fix
    fix = next((f for f in top["fixes"] if f), "Investigate subsystem manually")

    return {
        "root_cause": top["type"],
        "fix": fix,
        "confidence": confidence
    }

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

    patterns = preprocess_for_correlation(CURRENT_JOB["results"])

    candidates = build_correlation_candidates(patterns)

    final = smart_correlation(candidates)

    save_rca(CURRENT_JOB["path"], final)

    # Optional: DO NOT reset automatically (better for debugging)
    # CURRENT_JOB["id"] = None
    # CURRENT_JOB["path"] = None
    # CURRENT_JOB["results"] = []

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