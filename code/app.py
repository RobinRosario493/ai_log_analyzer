from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import re
from collections import defaultdict

app = Flask(__name__, template_folder="templates")
CORS(app)


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()


# ---------------- AI CALL ----------------
def ollama_analyze(sample):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3:8b",
                "prompt": f"""
You are an error log analyzer.

Return ONLY JSON:
{{
"type": "...",
"cause": "...",
"fix": "..."
}}

Error:
{sample}
""",
                "stream": False
            },
            timeout=120
        )

        data = response.json()

        # 🔴 IMPORTANT: actual AI text is inside "response"
        ai_text = data.get("response", "")

        start = ai_text.find("{")
        end = ai_text.rfind("}") + 1
        json_text = ai_text[start:end]

        parsed = json.loads(json_text)

        return parsed.get("type"), parsed.get("cause"), parsed.get("fix")

    except Exception as e:
        print("AI ERROR:", e)
        return "Unknown", "AI failed", "Check Ollama"





# ---------------- MAIN ----------------
def analyze_errors_only(log_text):

    lines = log_text.split("\n")

    # only error lines
    error_lines = [
        l for l in lines
        if any(x in l.lower() for x in [
            "error","exception","failed","critical","fatal"
        ])
    ]

    total_errors = len(error_lines)

    if total_errors == 0:
        return {"total_errors":0,"analysis":[]}

    print("Total ERROR lines:", total_errors)

    # group similar patterns
    groups = defaultdict(list)

    for line in error_lines:
        key = normalize(line)
        groups[key].append(line)

    print("Unique patterns:", len(groups))

    cards = []

    for i,(pattern,occ) in enumerate(groups.items(), start=1):

        count = len(occ)
        sample = occ[0].lower()

        print(f"[{i}/{len(groups)}] pattern count:", count)

        # known rules
        if "memory" in sample or "disk" in sample:
            t="Memory/Storage Error"
            c=f"{count} occurrences"
            f="Check system resources"

        elif "connection" in sample or "timeout" in sample:
            t="Network Error"
            c=f"{count} occurrences"
            f="Check network"

        elif "sql" in sample or "database" in sample:
            t="Database Error"
            c=f"{count} occurrences"
            f="Check DB"

        else:
            t, c, f = ollama_analyze(sample)


        cards.append({
            "error_line": sample,
            "type": t,
            "cause": c,
            "fix": f,
            "count": count
        })

    return {
        "total_errors": total_errors,
        "analysis": cards
    }


# ---------------- ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files["logfile"]
    log_text = file.read().decode("utf-8", errors="ignore")
    result = analyze_errors_only(log_text)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
