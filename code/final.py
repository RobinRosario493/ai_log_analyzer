from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re, os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, template_folder="templates")
CORS(app)

# ================= CONFIG =================
MODEL = "llama3:instruct"
AI_TIMEOUT = 120
MAX_WORKERS = 2
CONTEXT_BEFORE = 8
CONTEXT_AFTER = 5
MEMORY_FILE = "ai_memory.json"

session = requests.Session()
LAST_RESULT = None

# ================= MEMORY =================
if os.path.exists(MEMORY_FILE):
    with open(MEMORY_FILE, "r") as f:
        AI_MEMORY = json.load(f)
else:
    AI_MEMORY = {}

def save_memory():
    with open(MEMORY_FILE, "w") as f:
        json.dump(AI_MEMORY, f, indent=2)

# ================= HOME =================
@app.route("/")
def home():
    return render_template("final.html")

# ================= GROUP KEY =================
def group_key(line):
    parts = line.split("|")
    component = parts[3].lower() if len(parts) > 3 else "unknown"
    code = re.search(r'0x[0-9a-fA-F]+', line)
    code = code.group(0) if code else ""
    return f"{component}|{code}"

# ================= JSON SAFE =================
def extract_json(text):
    s = text.find("{")
    e = text.rfind("}") + 1
    if s == -1: return None
    try:
        return json.loads(text[s:e])
    except:
        try:
            t = text[s:e].replace("'", '"')
            t = re.sub(r",\s*}", "}", t)
            return json.loads(t)
        except:
            return None

# ================= AI CALL =================
def call_ai(sample, context):

    prompt = f"""
You are a senior production support engineer.

IMPORTANT:
- Group similar errors into SAME root cause
- Be consistent
- Provide REAL fix
- Detect if resolved automatically

Return JSON ONLY:

{{
"type":"...",
"cause":"...",
"fix":"...",
"root_signature":"short_unique_key",
"resolved": true/false
}}

Error:
{sample}

Context:
{context}
"""

    try:
        r = session.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=AI_TIMEOUT
        )

        data = r.json()
        parsed = extract_json(data.get("response", ""))

        if not parsed:
            return None

        return parsed

    except Exception as e:
        print("AI ERROR:", e)
        return None

# ================= PROCESS GROUP =================
def process_group(key, occ, lines):

    idx = occ[0][0]
    sample = occ[0][1]
    count = len(occ)

    context = "\n".join(
        lines[max(0, idx-CONTEXT_BEFORE):
        min(len(lines), idx+CONTEXT_AFTER)]
    )

    ai = call_ai(sample, context)

    if not ai:
        return None

    root = ai.get("root_signature", "GENERIC")

    # memory consistency
    if root in AI_MEMORY:
        mem = AI_MEMORY[root]
        ai["type"] = mem["type"]
        ai["cause"] = mem["cause"]
        ai["fix"] = mem["fix"]
    else:
        AI_MEMORY[root] = {
            "type": ai["type"],
            "cause": ai["cause"],
            "fix": ai["fix"]
        }
        save_memory()

    return {
        "type": ai["type"],
        "cause": ai["cause"],
        "fix": ai["fix"],
        "root": root,
        "count": count,
        "sample": sample[:200],
        "resolved": ai.get("resolved", False)
    }

# ================= ANALYZE =================
def analyze_logs(text):

    lines = text.split("\n")

    errors = [(i, l) for i, l in enumerate(lines)
              if "error" in l.lower() or "failed" in l.lower()]

    groups = defaultdict(list)
    for idx, line in errors:
        groups[group_key(line)].append((idx, line))

    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(process_group, k, o, lines)
                   for k, o in groups.items()]

        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    # merge root causes
    merged = {}
    for r in results:
        root = r["root"]
        if root not in merged:
            merged[root] = r
        else:
            merged[root]["count"] += r["count"]

    active = []
    resolved = []

    for r in merged.values():
        if r["resolved"]:
            resolved.append(r)
        else:
            active.append(r)

    return {
        "total_errors": len(errors),
        "active_issues": active,
        "resolved_issues": resolved
    }

# ================= ROUTES =================
@app.route("/analyze", methods=["POST"])
def analyze():
    global LAST_RESULT
    file = request.files["logfile"]
    text = file.read().decode("utf-8", "ignore")
    LAST_RESULT = analyze_logs(text)
    return jsonify(LAST_RESULT)

@app.route("/chat", methods=["POST"])
def chat():
    if not LAST_RESULT:
        return jsonify({"answer": "Upload logs first"})

    q = request.json.get("q", "")

    summary = json.dumps(LAST_RESULT["active_issues"], indent=2)

    prompt = f"""
You are a production support AI assistant.

System issues:
{summary}

User question:
{q}
"""

    r = session.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=90
    )

    data = r.json()
    return jsonify({"answer": data.get("response", "")})

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
