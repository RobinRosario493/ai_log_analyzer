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

CURRENT_JOB = {
    "id": None,
    "path": None,
    "results": [],
    "cancelled": False
}
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
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1,
                "num_predict": 300
                }
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

        severity = card.get("severity", "Low").lower()

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

    job_path = start_investigation()

    files = request.files.getlist("logfile")

    results = []

    for file in files:

        # Save raw file
        save_path = os.path.join(job_path, "logs", file.filename)
        file.save(save_path)

        # Read file
        with open(save_path, "r", errors="ignore") as f:
            text = f.read()

        # Analyze
        result = analyzeerrorsonly(text, file.filename)

        # Save HTML report
        html_path = os.path.join(
            job_path,
            "logs",
            file.filename + "_analysis.html"
        )

        save_html_report(
            html_path,
            file.filename,
            result["analysis"]
        )

        # Store results for this job
        results.append(result)
        CURRENT_JOB["results"].append(result)

    return jsonify({"files": results})

def normalize_log(line):
    line = line.lower()
    line = re.sub(r'\[.*?\]', '', line)
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'[0-9a-fA-F-]{36}', 'GUID', line)
    return line.strip()
def analyze_log_patterns_with_ai(samples):
 
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
    {chr(10).join(samples)}
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
 
        # ---------- Fallback: single object ----------
        elif text.startswith("{") and text.endswith("}"):
            data = [json.loads(text)]
 
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
        return []
 
def analyze_dotlog_file(log_text, filename):
 
    lines = log_text.splitlines()
    groups = defaultdict(list)
 
    # STEP 1: GROUP
    for i, line in enumerate(lines):
        if CURRENT_JOB["cancelled"]:
            print(".log grouping cancelled")
            return {"file": filename, "total_errors": 0, "analysis": []}

        key = normalize_log(line)[:150]
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
            severity = r.get("severity","Low")
 
            # show only medium/high
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



@app.route("/analyze_dotlogs", methods=["POST"])
def analyze_dotlogs():

    job_path = start_investigation()
    results = []

    files = request.files.getlist("logfile")

    for file in files:

        save_path = os.path.join(job_path, "dotlogs", file.filename)
        file.save(save_path)

        with open(save_path, "r", errors="ignore") as f:
            text = f.read()

        result = analyze_dotlog_file(text, file.filename)

        html_path = os.path.join(
            job_path,
            "dotlogs",
            file.filename + "_analysis.html"
        )

        save_html_report(
            html_path,
            file.filename,
            result["analysis"]
        )

        results.append(result)
        CURRENT_JOB["results"].append(result)

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
 
# ---------------- DUMP ROUTE ----------------
@app.route("/analyze_dumps", methods=["POST"])
def analyze_dumps():

    job_path = start_investigation()

    dumpfiles = request.files.getlist("dumpfile")
    pdbfiles = request.files.getlist("pdbfile")

    results = []

    for i, dump in enumerate(dumpfiles):

        if CURRENT_JOB["cancelled"]:
            return jsonify({"cancelled": True})

        # Save dump inside job folder
        dump_path = os.path.join(job_path, "dumps", dump.filename)
        dump.save(dump_path)

        # Optional PDB
        pdbpath = None
        if i < len(pdbfiles):
            pdb = pdbfiles[i]
            if pdb.filename.endswith(".pdb"):
                pdbpath = os.path.join(PDB_UPLOAD_DIR, pdb.filename)
                pdb.save(pdbpath)

        # Run WinDbg
        windbg_output = runwindbg(dump_path, pdbpath)

        if not windbg_output:
            root_cause = "WinDbg failed to produce output."
            fix = "Verify dump file integrity and debugger installation."
            bugcheck = ""
            driver = ""
            subsystem = ""
        else:
            ai_text = analyzedumpai(windbg_output)

            print("========== RAW AI OUTPUT ==========")
            print(repr(ai_text))
            print("===================================")

            clean_text = ai_text.replace("```json", "").replace("```", "").strip()

            # Extract JSON safely
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
                except Exception as e:
                    print("JSON parse error:", e)
                    root_cause = clean_text
                    fix = "Manual review required."
            else:
                root_cause = clean_text
                fix = "Manual review required."

        if not root_cause:
            root_cause = "AI did not provide detailed root cause."

        if not fix:
            fix = "Manual review required."

        # Build rich explanation
        formatted_cause = (
            f"Bugcheck: {bugcheck or 'Unknown'}\n"
            f"Faulting Driver: {driver or 'Unknown'}\n"
            f"Subsystem: {subsystem or 'Unknown'}\n\n"
            f"Detailed Analysis:\n{root_cause}"
        )

        dump_result = {
            "file": dump.filename,
            "analysis": [{
                "type": "Crash Dump",
                "cause": formatted_cause,
                "fix": fix,
                "count": 1,
                "severity": "High"
            }]
        }

        # Save HTML
        html_path = os.path.join(
            job_path,
            "dumps",
            dump.filename + "_analysis.html"
        )

        save_html_report(
            html_path,
            dump.filename,
            dump_result["analysis"]
        )

        results.append(dump_result)
        CURRENT_JOB["results"].append(dump_result)

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
        if CURRENT_JOB["cancelled"]:
            print("ETL row parsing cancelled")
            return {"file": filename, "patterns": []}
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
    patterns = list(set(patterns))
    patterns = patterns[:10]
    return {
        "file": filename,
        "patterns": patterns
    }
 
def analyze_etl_with_ai(patterns):
    samples = [p[0] + " : " + p[1] for p in patterns[:5]]
 
    prompt = f"""
You are a Windows ETL diagnostics expert.
 
Only explain what can be proven from the patterns.
Do NOT assume CPU, disk, or network issues unless explicitly stated.
 
Return JSON:
type, cause, fix, severity.
 
Patterns:
{chr(10).join(samples)}
"""
 
    return callai(prompt,timeout=120)



@app.route("/analyze_etl", methods=["POST"])
def analyze_etl():

    job_path = start_investigation()
    files = request.files.getlist("etlfile")
    results = []

    for file in files:

        if CURRENT_JOB["cancelled"]:
            return jsonify({"cancelled": True})

        name = file.filename
        save_path = os.path.join(job_path, "etl", name)
        file.save(save_path)

        csv_text = convert_etl_to_text(save_path)

        if not csv_text:
            result = {
                "file": name,
                "total_errors": 0,
                "analysis": []
            }
        else:
            behavior = analyze_etl_behavior(csv_text, name)

            if not behavior["patterns"]:
                behavior["patterns"] = [
                    ("Normal behavior detected", "No anomalies found")
                ]

            ai_text = analyze_etl_with_ai(behavior["patterns"])

            cards = []
            for p in behavior["patterns"]:
                cards.append({
                    "file": name,
                    "error_line": p[0],
                    "type": "Behavior Pattern",
                    "cause": p[1],
                    "fix": ai_text[:200],
                    "count": 1,
                    "status": "Active",
                    "severity": "Info"
                })

            result = {
                "file": name,
                "total_errors": len(cards),
                "analysis": cards
            }

        # ✅ Save HTML
        html_path = os.path.join(
            job_path,
            "etl",
            name + "_analysis.html"
        )

        save_html_report(
            html_path,
            name,
            result["analysis"]
        )

        results.append(result)
        CURRENT_JOB["results"].append(result)

    return jsonify({"files": results})


def preprocess_for_correlation(all_results):

    severity_weight = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 1
    }

    weighted = []

    for file in all_results:
        for card in file.get("analysis", []):
            if not isinstance(card, dict):
                continue
            cause = card.get("type")
            fix = card.get("fix")
            severity = card.get("severity", "Low")

            if severity in ["Low", "Info"]:
                continue            
            count = card.get("count", 1)

            weight = severity_weight.get(severity, 1) * count

            for _ in range(weight):
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
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object found in AI output")

        json_block = text[start:end+1]
        return json.loads(json_block)

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
    app.run(host="127.0.0.1", port=5000, debug=True)