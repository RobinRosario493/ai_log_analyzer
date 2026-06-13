from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# ================= CONFIG =================
MODEL = "llama3:8b"
AI_TIMEOUT = 120

session = requests.Session()

# ================= HOME =================
@app.route("/")
def home():
    return render_template("n1.html")

# ================= GROUP KEY =================
def group_key(line):
    parts = line.split("|")
    component = parts[3].lower() if len(parts) > 3 else "unknown"

    code_match = re.search(r'0x[0-9a-fA-F]+', line)
    code = code_match.group(0) if code_match else ""

    return f"{component}|{code}"

# ================= JSON EXTRACT =================
def extract_json(text):

    if not text:
        return None

    # remove markdown
    text = text.replace("```json", "").replace("```", "")

    start = text.find("[")
    end = text.rfind("]")

    if start == -1 or end == -1:
        return None

    json_str = text[start:end+1]

    try:
        return json.loads(json_str)
    except Exception as e:
        print("JSON PARSE FAIL:", e)
        print("RAW TEXT:", text)
        return None

# ================= AI CLASSIFIER =================
def classify_batch_ai(blocks):

    prompt = f"""
Return ONLY valid JSON list.
No explanation text.

[
{{
"type":"error name",
"cause":"root cause",
"fix":"fix",
"signature":"id",
"status":"active or resolved",
"confidence":"0-100"
}}
]

Logs:
{blocks}
"""

    try:
        r = session.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=AI_TIMEOUT
        )

        data = r.json()

        print("\n=========== RAW AI RESPONSE ===========\n")
        print(data.get("response"))
        print("\n======================================\n")

        parsed = extract_json(data.get("response", ""))
        return parsed

    except Exception as e:
        print("AI ERROR:", e)
        return None

# ================= ANALYSIS =================
def analyze_logs(text):

    lines = text.split("\n")

    errors = [(i,l) for i,l in enumerate(lines)
              if "error" in l.lower() or "failed" in l.lower()]

    if not errors:
        return {
            "total_errors":0,
            "active_issues":[],
            "resolved_issues":[]
        }

    groups = defaultdict(list)

    for idx,line in errors:
        groups[group_key(line)].append((idx,line))

    blocks=[]
    keys=[]

    for key,occ in groups.items():

        idx = occ[0][0]

        context = "\n".join(
            lines[max(0,idx-10): idx+20]
        )

        block=f"""
ERROR:
{occ[0][1]}

CONTEXT:
{context}
"""

        blocks.append(block)
        keys.append(key)

    ai_results = classify_batch_ai("\n\n".join(blocks))

    active=[]
    resolved=[]

    # 🔴 IF AI FAILS → fallback output
    if not ai_results:
        print("AI returned nothing — using fallback")

        for key, occ in groups.items():
            active.append({
                "type":"Error Detected",
                "cause":"AI parsing failed",
                "fix":"Check logs manually",
                "signature":key,
                "count":len(occ),
                "confidence":"50",
                "sample":occ[0][1][:200]
            })

        return {
            "total_errors":len(errors),
            "active_issues":active,
            "resolved_issues":[]
        }

    # 🔵 AI SUCCESS
    for i,res in enumerate(ai_results):

        key = keys[i]
        occ = groups[key]

        item = {
            "type":res.get("type","Unknown"),
            "cause":res.get("cause",""),
            "fix":res.get("fix",""),
            "signature":res.get("signature",key),
            "count":len(occ),
            "confidence":res.get("confidence",""),
            "sample":occ[0][1][:200]
        }

        if res.get("status","active")=="active":
            active.append(item)
        else:
            resolved.append(item)

    return {
        "total_errors":len(errors),
        "active_issues":active,
        "resolved_issues":resolved
    }

# ================= ROUTE =================
@app.route("/analyze", methods=["POST"])
def analyze():

    if "logfile" not in request.files:
        return jsonify({
            "total_errors":0,
            "active_issues":[],
            "resolved_issues":[]
        })

    file = request.files["logfile"]
    text = file.read().decode("utf-8","ignore")

    result = analyze_logs(text)
    return jsonify(result)

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
