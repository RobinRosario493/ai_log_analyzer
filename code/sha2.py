from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, os, re, subprocess
from collections import defaultdict

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:instruct"   # faster & stable
LAST_ANALYSIS = ""

# ================= HOME =================
@app.route("/")
def home():
    return render_template("sha2.html")

# =========================================================
# 🔥 LOG ANALYSIS
# =========================================================
def analyze_log(text, filename):

    print("Processing LOG:", filename)

    lines = text.split("\n")
    errors = []

    for l in lines:
        if any(x in l.lower() for x in ["error","failed","exception","fatal"]):
            errors.append(l)

    groups = defaultdict(list)

    for e in errors:
        key = re.sub(r'\d+', 'X', e.lower())
        groups[key].append(e)

    results = []

    for k,occ in list(groups.items())[:20]:

        sample = occ[0]

        prompt = f"""
Explain this system error.

Error:
{sample}

Give:
- error type
- root cause
- fix
"""

        try:
            r = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": MODEL, "prompt": prompt, "stream": False},
                timeout=60
            )
            ai = r.json().get("response","")
        except:
            ai = "AI analysis failed"

        results.append({
            "file": filename,
            "error": sample,
            "count": len(occ),
            "analysis": ai
        })

    return {
        "file": filename,
        "total_errors": len(errors),
        "analysis": results
    }

# =========================================================
# 🔥 DUMP ANALYSIS
# =========================================================
def analyze_dump(path, filename):

    print("Processing DUMP:", filename)

    # fallback text read
    try:
        with open(path, "rb") as f:
            data = f.read(2000000)
            text = data.decode(errors="ignore")
    except:
        text = "Could not read dump"

    prompt = f"""
Analyze this Windows crash dump.

Give:
- crash type
- root cause
- failing module
- fix

{text[:3000]}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )
        ai = r.json().get("response","")
    except:
        ai = "AI dump analysis failed"

    return {
        "file": filename,
        "analysis": ai
    }

# =========================================================
# 🔥 MAIN ANALYZE ROUTE
# =========================================================
@app.route("/analyze", methods=["POST"])
def analyze():

    global LAST_ANALYSIS

    files = request.files.getlist("logfile")
    print("FILES RECEIVED:", [f.filename for f in files])

    log_results = []
    dump_results = []

    for f in files:

        name = f.filename.lower()

        # LOG
        if name.endswith(".log"):
            text = f.read().decode("utf-8","ignore")
            r = analyze_log(text, f.filename)
            log_results.append(r)

        # DUMP
        elif name.endswith(".dmp"):
            path = "temp_"+f.filename
            f.save(path)
            r = analyze_dump(path, f.filename)
            dump_results.append(r)

    LAST_ANALYSIS = str(log_results)[:2000]

    return jsonify({
        "logs": log_results,
        "dumps": dump_results
    })

# =========================================================
# 🔥 ASK AI
# =========================================================
@app.route("/ask_ai", methods=["POST"])
def ask_ai():

    error = request.json.get("error","")

    prompt = f"Explain and give fix:\n{error}"

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=60
    )

    return jsonify({"answer": r.json().get("response","")})

# =========================================================
# 🔥 CHATBOT
# =========================================================
@app.route("/chat", methods=["POST"])
def chat():

    msg = request.json.get("message","")

    prompt = f"""
You are system support AI.

Logs summary:
{LAST_ANALYSIS}

User:
{msg}
"""

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=120
    )

    return jsonify({"reply": r.json().get("response","")})

# =========================================================
if __name__ == "__main__":
    print("SERVER STARTED")
    app.run(debug=True)
