from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

# ---------------- CONFIG ----------------
MODEL = "phi3"   # use "phi3" if laptop slow
MAX_WORKERS = 1           # 1–2 best for Windows
AI_LEVELS = ["Critical","Error","Warning","Diagnostic"]

ai_cache = {}
session = requests.Session()   # 🔥 persistent session fixes socket error

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("all.html")

# ---------------- LEVEL DETECTION ----------------
def detect_level(line):
    l = line.lower()
    if "tracein" in l: return "TraceIn"
    if "traceout" in l: return "TraceOut"
    if "verbose" in l: return "Verbose"
    if "diag" in l: return "Diagnostic"
    if "information" in l or "|info|" in l: return "Information"
    if "warning" in l: return "Warning"
    if "error" in l: return "Error"
    if "critical" in l or "fatal" in l: return "Critical"
    return "Unknown"

# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

# ---------------- AI CALL ----------------
def infer_type(sample):
    s = sample.lower()

    if "timeout" in s: return "Timeout Error"
    if "memory" in s: return "Memory Error"
    if "disk" in s: return "Disk Error"
    if "connection" in s: return "Network Error"
    if "database" in s or "sql" in s: return "Database Error"
    if "permission" in s or "access denied" in s: return "Permission Error"
    if "file not found" in s: return "File Error"
    if "service" in s: return "Service Error"

    return "General Error"


def ollama_analyze(sample):
    if sample in ai_cache:
        return ai_cache[sample]

    try:
        response = session.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": f"""
Return ONLY valid JSON.

Format:
{{"type":"...","cause":"...","fix":"..."}}

Do not explain.
Do not add text.

Log:
{sample}
""",
                "stream": False,
                "options": {"temperature":0}
            },
            timeout=60
        )

        data = response.json()
        ai_text = data.get("response","").strip()

        # Try extract JSON
        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1

        if start == -1:
            t = infer_type(sample)
            return (t,"Auto detected","Check logs")

        json_text = ai_text[start:end]

        try:
            parsed = json.loads(json_text)
        except:
            t = infer_type(sample)
            return (t,"Auto detected","Check logs")

        t = parsed.get("type","Unknown")
        c = parsed.get("cause","Unknown")
        f = parsed.get("fix","Check logs")

        # If still unknown → fallback
        if t.lower() == "unknown":
            t = infer_type(sample)

        result = (t,c,f)
        ai_cache[sample] = result
        return result

    except Exception as e:
        print("AI ERROR:", e)
        t = infer_type(sample)
        return (t,"AI failed","Check logs")


# ---------------- PROCESS PATTERN ----------------
def process_pattern(pattern, occ):
    count = len(occ)
    sample = occ[0]
    level = detect_level(sample)

    if "memory" in sample:
        t,c,f = "Memory Error","High memory usage","Increase memory"
    elif "timeout" in sample:
        t,c,f = "Timeout","Service timeout","Check connectivity"
    elif level not in AI_LEVELS:
        t,c,f = level,"Normal log level","No action required"
    else:
        t,c,f = ollama_analyze(sample)

    return {
        "error_line": sample[:200],
        "type": t,
        "cause": c,
        "fix": f,
        "count": count,
        "level": level
    }

# ---------------- MAIN ----------------
def analyze_logs(log_text):
    lines = log_text.split("\n")

    level_counts = defaultdict(int)
    for line in lines:
        level_counts[detect_level(line)] += 1

    groups = defaultdict(list)
    for line in lines:
        key = normalize(line)
        groups[key].append(line)

    cards = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_pattern,p,o) for p,o in groups.items()]
        for f in as_completed(futures):
            cards.append(f.result())

    top = sorted(cards,key=lambda x:x["count"],reverse=True)[:5]

    return {
        "total_lines": len(lines),
        "patterns": len(groups),
        "level_counts": level_counts,
        "analysis": cards,
        "top": top
    }

# ---------------- ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files["logfile"]
    text = file.read().decode("utf-8",errors="ignore")
    result = analyze_logs(text)
    return jsonify(result)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)   # 🔥 important fix
