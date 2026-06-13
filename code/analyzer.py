import os
import subprocess
import json
import csv
import re
from collections import defaultdict
from datetime import datetime
from io import StringIO

# import from core backend
from chat import call_ai, extract_json, save_html_report, CURRENT_JOB, start_investigation, PDB_UPLOAD_DIR

# ---------------- ERROR SIGNATURE EXTRACTION ----------------

def extract_signature(line):

    l = line.lower()

    if "nullreferenceexception" in l:
        return "NullReferenceException"

    if "timeout" in l:
        return "Timeout"

    if "access denied" in l:
        return "AccessDenied"

    if "crash" in l:
        return "Crash"

    if "exception" in l:
        return "Exception"

    return l[:120]


# ---------------- CONTEXT WINDOW ----------------

def get_context(lines, index, window=3):

    start = max(0, index-window)
    end = min(len(lines), index+window+1)

    return " ".join(lines[start:end])


# ---------------- AI BULK ANALYZER ----------------

def ai_bulk_analyze(samples):

    if not samples:
        return []

    prompt = f"""
You are a senior Windows reliability engineer.

Classify each log failure.

Return JSON array:

[
{{
"type":"",
"cause":"",
"fix":"",
"severity":"Low|Medium|High"
}}
]

Events:
{chr(10).join(samples)}
"""

    response = call_ai(prompt, timeout=300)

    try:
        return json.loads(response)

    except:

        start = response.find("[")
        end = response.rfind("]")

        if start != -1 and end != -1:
            return json.loads(response[start:end+1])

    return []


# ---------------- LOG ANALYZER ----------------

def analyze_log_file(text, filename):

    lines = text.splitlines()

    grouped = defaultdict(list)

    total_errors = 0

    for i,line in enumerate(lines):

        if CURRENT_JOB["cancelled"]:
            return {"file":filename,"analysis":[]}

        l = line.lower()

        if not any(word in l for word in [
            "error","fail","exception","timeout","crash"
        ]):
            continue

        total_errors += 1

        signature = extract_signature(line)

        key = signature

        grouped[key].append((i,line))


    samples = []
    keys = []

    for key,rows in grouped.items():

        idx,line = rows[0]

        context = get_context(lines,idx)

        samples.append(context)
        keys.append(key)


    ai_results = []

    batch_size = 6

    for i in range(0,len(samples),batch_size):

        chunk = samples[i:i+batch_size]

        ai_results.extend(ai_bulk_analyze(chunk))


    cards = []

    for key,rows in grouped.items():

        idx = keys.index(key)

        count = len(rows)

        sample = rows[0][1]

        result = ai_results[idx] if idx < len(ai_results) else {}

        cards.append({

            "file":filename,
            "error_line":sample,
            "type":result.get("type","Unknown"),
            "cause":result.get("cause","Unknown"),
            "fix":result.get("fix","Manual investigation required"),
            "severity":result.get("severity","Medium"),
            "count":count
        })


    return {
        "file":filename,
        "total_errors":total_errors,
        "analysis":cards
    }


# ---------------- NORMALIZE STRUCTURED LOG ----------------

def normalize_log(line):

    line = line.lower()

    line = re.sub(r'\[.*?\]', '', line)
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+','HEX',line)

    return line.strip()


# ---------------- DOTLOG ANALYZER ----------------

def analyze_dotlog_file(text, filename):

    lines = text.splitlines()

    groups = defaultdict(list)

    for i,line in enumerate(lines):

        key = normalize_log(line)[:150]

        groups[key].append((i,line))


    samples=[]
    keys=[]

    for key,occ in groups.items():

        samples.append(occ[0][1])
        keys.append(key)


    ai_results=[]

    batch=6

    for i in range(0,len(samples),batch):

        chunk=samples[i:i+batch]

        ai_results.extend(ai_bulk_analyze(chunk))


    cards=[]

    for key,occ in groups.items():

        idx=keys.index(key)

        count=len(occ)

        sample=occ[0][1]

        r=ai_results[idx] if idx<len(ai_results) else {}

        if r.get("severity","Low")=="Low":
            continue

        cards.append({

            "file":filename,
            "error_line":sample,
            "type":r.get("type","Unknown"),
            "cause":r.get("cause","Unknown"),
            "fix":r.get("fix","Manual investigation required"),
            "severity":r.get("severity","Medium"),
            "count":count
        })

    return {

        "file":filename,
        "analysis":cards
    }


# ---------------- ETL DECODER ----------------

def convert_etl_to_csv(etl_path):

    csv_out = etl_path+"_decoded.csv"

    cmd=[
        "powershell",
        "-Command",
        f"""
        Get-WinEvent -Path '{etl_path}' -Oldest |
        Select TimeCreated,ProviderName,Id,Message |
        Export-Csv '{csv_out}' -NoTypeInformation
        """
    ]

    try:

        subprocess.run(cmd,timeout=600)

    except:

        return ""

    if os.path.exists(csv_out):

        with open(csv_out,"r",errors="ignore") as f:

            return f.read()

    return ""


# ---------------- ETL BEHAVIOR DETECTOR ----------------

def analyze_etl_behavior(csv_text,filename):

    reader=csv.DictReader(StringIO(csv_text))

    rows=list(reader)

    patterns=[]

    provider_counts=defaultdict(int)

    timestamps=[]

    for r in rows:

        msg=(r.get("Message") or "").lower()

        provider=r.get("ProviderName","Unknown")

        provider_counts[provider]+=1

        if "retry" in msg:
            patterns.append(("Retry activity detected",msg))

        if "timeout" in msg:
            patterns.append(("Timeout detected",msg))

        if "crash" in msg:
            patterns.append(("Crash indicator",msg))


    for provider,count in provider_counts.items():

        if count>50:

            patterns.append(("High activity loop",provider))


    if not patterns:

        patterns.append(("Normal behavior","No anomalies detected"))


    cards=[]

    for p in patterns:

        cards.append({

            "file":filename,
            "error_line":p[0],
            "type":"Behavior Pattern",
            "cause":p[1],
            "fix":"Investigate subsystem generating events",
            "severity":"Info",
            "count":1
        })

    return {

        "file":filename,
        "analysis":cards
    }


# ---------------- WINDBG EXECUTION ----------------

WINDBG=r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"

def run_windbg(dump_path,pdb_path=None):

    logfile=dump_path+"_windbg.txt"

    cmd=[WINDBG,"-z",dump_path]

    if pdb_path:

        cmd+=["-y",PDB_UPLOAD_DIR]

    cmd+=["-logo",logfile,"-c","!analyze -v; lm; k; q"]

    try:

        subprocess.run(cmd,timeout=300)

    except:

        return ""

    if os.path.exists(logfile):

        with open(logfile,"r",errors="ignore") as f:

            return f.read()

    return ""


# ---------------- DUMP AI ANALYSIS ----------------

def analyze_dump_output(text):

    prompt=f"""
You are a senior Windows kernel crash analyst.

Analyze WinDbg output.

Return JSON:

{{
"type":"Crash",
"cause":"",
"fix":"",
"severity":"High"
}}

{text[:8000]}
"""

    response=call_ai(prompt)

    return extract_json(response)