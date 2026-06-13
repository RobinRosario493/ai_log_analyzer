from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:instruct"
AI_TIMEOUT = 60
session = requests.Session()

LAST_RESULT = None

# ---------- HOME ----------
@app.route("/")
def home():
    return render_template("index5.html")

# ---------- GROUP KEY ----------
def group_key(line):
    parts = line.split("|")
    component = parts[3].lower() if len(parts) > 3 else "unknown"

    code_match = re.search(r'0x[0-9a-fA-F]+', line)
    code = code_match.group(0) if code_match else ""

    return f"{component}|{code}"

# ---------- SAFE JSON ----------
def extract_json(text):
    s = text.find("{")
    e = text.rfind("}") + 1
    if s == -1:
        return None
    try:
        return json.loads(text[s:e])
    except:
        try:
            t = text[s:e].replace("'", '"')
            return json.loads(t)
        except:
            return None

# ---------- AI CALL ----------
def call_ai(sample, context):

    prompt = f"""
You are a senior production support engineer.

Group similar errors into ONE root cause.

Return JSON only:
{{
"type":"single error name",
"cause":"root cause",
"fix":"clear fix",
"root_signature":"short_id"
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

        fix = parsed.get("fix", "Restart related service")
        if not fix or fix.lower() == "none":
            fix = "Restart related service and verify dependencies"

        return (
            parsed.get("type", "System Error"),
            parsed.get("cause", "Unknown cause"),
            fix,
            parsed.get("root_signature", "GENERIC"),
            "ai"
        )

    except Exception as e:
        print("AI ERROR:", e)
        return None

# ---------- FALLBACK ----------
def fallback(sample):
    return (
        "System Error",
        "Configuration or dependency issue",
        "Restart service and verify dependencies",
        "GENERIC",
        "fallback"
    )

# ---------- PROCESS ----------
def process_group(key, occ, lines):

    idx = occ[0][0]
    sample = occ[0][1]
    count = len(occ)

    context = "\n".join(lines[max(0, idx-3): idx+2])

    ai = call_ai(sample, context)

    if ai:
        t, c, f, root, source = ai
    else:
        t, c, f, root, source = fallback(sample)

    return {
        "type": t,
        "cause": c,
        "fix": f,
        "root": root,
        "count": count,
        "sample": sample[:200],
        "source": source
    }

# ---------- ANALYZE ----------
def analyze_logs(text):

    lines = text.split("\n")

    errors = [(i, l) for i, l in enumerate(lines)
              if "error" in l.lower() or "failed" in l.lower()]

    groups = defaultdict(list)
    for idx, line in errors:
        groups[group_key(line)].append((idx, line))

    active = []

    for k, occ in groups.items():
        r = process_group(k, occ, lines)
        active.append(r)

    # merge same root
    merged = {}
    for item in active:
        root = item["root"]
        if root not in merged:
            merged[root] = item
        else:
            merged[root]["count"] += item["count"]

    return {
        "total_errors": len(errors),
        "active_issues": list(merged.values()),
        "resolved_issues": []
    }

# ---------- ROUTES ----------
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
        return jsonify({"answer": "Upload logs first."})

    q = request.json.get("q", "")

    summary = json.dumps(LAST_RESULT["active_issues"], indent=2)

    prompt = f"""
You are an AI production support assistant.

System issues:
{summary}

User question:
{q}
"""

    r = session.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=60
    )

    data = r.json()
    return jsonify({"answer": data.get("response", "No answer")})

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
 