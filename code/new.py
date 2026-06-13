from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict

app = Flask(__name__, template_folder="templates")
CORS(app)

# ================= CONFIG =================
MODEL = "llama3:8b"
AI_TIMEOUT = 90

session = requests.Session()
LAST_RESULT = None
AI_CACHE = {}

# ================= HOME =================
@app.route("/")
def home():
    return render_template("new.html")

# ================= GROUPING =================
def group_key(line):
    parts = line.split("|")
    component = parts[3].lower() if len(parts) > 3 else "unknown"
    code_match = re.search(r'0x[0-9a-fA-F]+', line)
    code = code_match.group(0) if code_match else ""
    return f"{component}|{code}"

# ================= JSON PARSER =================
def extract_json(text):
    s = text.find("{")
    e = text.rfind("}") + 1
    if s == -1:
        return None
    try:
        return json.loads(text[s:e])
    except:
        try:
            fixed = text[s:e].replace("'", '"')
            return json.loads(fixed)
        except:
            return None

# ================= FALLBACK ERROR TYPE =================
def fallback_type(sample):
    s = sample.lower()

    if "timeout" in s:
        return "Timeout Error"
    if "connection" in s or "refused" in s:
        return "Connection Error"
    if "auth" in s:
        return "Authentication Error"
    if "null" in s:
        return "Null Pointer Error"
    if "memory" in s:
        return "Memory Error"
    if "file" in s:
        return "File Error"

    return "System Error"

# ================= AI CALL =================
def call_ai(sample, context):

    cache_key = hash(sample + context)
    if cache_key in AI_CACHE:
        return AI_CACHE[cache_key]

    prompt = f"""
You are a senior production support engineer.

Return ONLY valid JSON.
Do not write explanation text.

Format:
{{
"type": "short error category",
"cause": "exact root cause",
"fix": "clear fix",
"root_signature": "unique id"
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

        result = (
            parsed.get("type", fallback_type(sample)),
            parsed.get("cause", "Unknown cause"),
            parsed.get("fix", "Check logs"),
            parsed.get("root_signature", "GENERIC"),
            "ai"
        )

        AI_CACHE[cache_key] = result
        return result

    except Exception as e:
        print("AI ERROR:", e)
        return None

# ================= ANALYZE =================
def analyze_logs(text):

    lines = text.split("\n")

    errors = [(i, l) for i, l in enumerate(lines)
              if "error" in l.lower() or "failed" in l.lower()]

    if not errors:
        return {"total_errors": 0, "active_issues": [], "resolved_issues": []}

    groups = defaultdict(list)
    for idx, line in errors:
        groups[group_key(line)].append((idx, line))

    results = []

    for key, occ in groups.items():

        idx = occ[0][0]
        sample = occ[0][1]
        count = len(occ)

        context = "\n".join(lines[max(0, idx-5): idx+5])

        ai = call_ai(sample, context)

        if not ai:
            results.append({
                "type": fallback_type(sample),
                "cause": "AI could not determine",
                "fix": "Check logs manually",
                "root": key,
                "count": count,
                "sample": sample[:300],
                "source": "fallback"
            })
            continue

        t, c, f, root, source = ai

        results.append({
            "type": t,
            "cause": c,
            "fix": f,
            "root": root,
            "count": count,
            "sample": sample[:300],
            "source": source
        })

    merged = {}
    for item in results:
        r = item["root"]
        if r not in merged:
            merged[r] = item
        else:
            merged[r]["count"] += item["count"]

    return {
        "total_errors": len(errors),
        "active_issues": list(merged.values()),
        "resolved_issues": []
    }

# ================= ANALYZE ROUTE =================
@app.route("/analyze", methods=["POST"])
def analyze():
    global LAST_RESULT

    file = request.files["logfile"]
    text = file.read().decode("utf-8", "ignore")

    LAST_RESULT = analyze_logs(text)
    return jsonify(LAST_RESULT)

# ================= CHAT =================
@app.route("/chat", methods=["POST"])
def chat():

    global LAST_RESULT

    if not LAST_RESULT:
        return jsonify({"answer": "Upload logs first"})

    q = request.json.get("q", "")

    issues = LAST_RESULT["active_issues"][:5]

    summary = "\n".join(
        [f"{x['type']} | {x['count']} | {x['cause']}" for x in issues]
    )

    prompt = f"""
You are a production support AI.

System issues detected:
{summary}

User question:
{q}

Answer briefly and clearly.
"""

    try:
        r = session.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )

        data = r.json()
        return jsonify({"answer": data.get("response", "No response")})

    except Exception as e:
        print("CHAT ERROR:", e)
        return jsonify({"answer": "AI not responding"})

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
