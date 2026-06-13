from flask import Flask, request, jsonify, render_template
import requests
import os
import subprocess
import time

app = Flask(__name__)

MODEL = "llama3:instruct"

# ================= HOME =================
@app.route("/")
def home():
    return render_template("dump1.html")

# =========================================================
# 🔥 RUN WINDBG ON DUMP
# =========================================================


def run_windbg(dump_path):

    print("Running WinDbg on:", dump_path)

    WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"

    cmd = [
        WINDBG,
        "-z", dump_path,
        "-c", "!analyze -v; q"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180
    )

    return result.stdout



# =========================================================
# 🔥 AI ANALYSIS
# =========================================================
def analyze_with_ai(text):

    print("Sending WinDbg output to AI...")

    prompt = f"""
You are a senior Windows crash dump analyst.

From this WinDbg crash analysis identify:

1. Bugcheck code
2. Faulty driver/module
3. Root cause
4. Whether this is an audio/driver crash
5. Recommended fix

WinDbg Output:
{text[:4000]}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        return r.json().get("response", "AI returned empty")

    except Exception as e:
        print("AI ERROR:", e)
        return "AI analysis failed"

# =========================================================
# 🔥 ANALYZE ROUTE
# =========================================================
@app.route("/analyze", methods=["POST"])
def analyze():

    if "dumpfile" not in request.files:
        return jsonify({"result": "No file uploaded"})

    file = request.files["dumpfile"]
    name = file.filename

    print("Received dump:", name)

    path = "temp_dump.dmp"
    file.save(path)

    # 🔥 run windbg instead of reading binary
    text = run_windbg(path)

    # 🔥 send windbg output to AI
    ai = analyze_with_ai(text)

    return jsonify({
        "file": name,
        "analysis": ai
    })

# =========================================================
if __name__ == "__main__":
    print("DUMP ANALYZER STARTED")
    app.run(debug=True)
