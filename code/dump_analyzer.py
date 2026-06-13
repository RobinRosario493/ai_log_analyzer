from flask import Flask, request, jsonify, render_template
import requests
import os
import subprocess
import re

app = Flask(__name__)

MODEL = "llama3:instruct"
WINDBG = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"

# ================= HOME =================
@app.route("/")
def home():
    return render_template("dump.html")

# =========================================================
# RUN WINDBG
# =========================================================
def run_windbg(dump_path):

    print("\n========== RUNNING WINDBG ==========")
    print("Dump:", dump_path)

    log_file = "windbg_output.txt"

    cmd = [
        WINDBG,
        "-z", dump_path,
        "-logo", log_file,
        "-c", "!analyze -v; q"
    ]

    subprocess.run(cmd, timeout=300)

    print("WINDBG FINISHED")

    if os.path.exists(log_file):
        with open(log_file, "r", errors="ignore") as f:
            data = f.read()

        print("Output size:", len(data))
        print("Preview:\n", data[:300])
        return data

    print("No WinDbg output found")
    return ""

# =========================================================
# CLEAN OUTPUT
# =========================================================
def clean_output(text):

    start = text.find("BugCheck")
    if start == -1:
        return text[:12000]

    return text[start:start+12000]

# =========================================================
# EXTRACT INFO (IMPORTANT)
# =========================================================
def extract_info(text):

    bugcheck = "Unknown"
    driver = "Unknown"
    module = "Unknown"

    m = re.search(r"BugCheck\s+(\w+)", text)
    if m:
        bugcheck = m.group(1)

    m = re.search(r"Probably caused by:\s+(\S+)", text)
    if m:
        driver = m.group(1)

    m = re.search(r"MODULE_NAME:\s+(\S+)", text)
    if m:
        module = m.group(1)

    # fallback for exception dumps
    if driver == "Unknown":
        m = re.search(r"IMAGE_NAME:\s+(\S+)", text)
        if m:
            driver = m.group(1)

    return bugcheck, driver, module

# =========================================================
# AUDIO DETECTION
# =========================================================
def is_audio(text):
    keywords = ["audio", "realtek", "hdaudio", "rtkv", "codec"]
    for k in keywords:
        if k in text.lower():
            return True
    return False

# =========================================================
# AI SUMMARY (secondary only)
# =========================================================
def ai_summary(text):

    prompt = f"""
Summarize this Windows crash dump in 3 lines.
Focus on root cause and driver.

{text}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=120
        )
        return r.json().get("response", "")
    except:
        return "AI summary unavailable"

# =========================================================
# ANALYZE ROUTE
# =========================================================
@app.route("/analyze", methods=["POST"])
def analyze():

    print("\n==============================")
    print("ANALYZE ROUTE STARTED")
    print("==============================")

    files = request.files.getlist("dumpfile")

    if not files:
        print("No files uploaded")
        return jsonify({"result": "No files uploaded"})

    results = []

    for file in files:

        name = file.filename
        print("\nProcessing:", name)

        path = f"temp_{name}"
        file.save(path)

        text = run_windbg(path)
        cleaned = clean_output(text)

        bugcheck, driver, module = extract_info(cleaned)
        audio_flag = is_audio(cleaned)

        # strong fallback message
        if driver == "Unknown":
            root = "Likely application/exception crash"
        else:
            root = f"Crash caused by driver {driver}"

        ai = ai_summary(cleaned)

        results.append({
            "file": name,
            "bugcheck": bugcheck,
            "driver": driver,
            "module": module,
            "audio_related": audio_flag,
            "root_cause": root,
            "ai_summary": ai
        })

    print("\nANALYSIS COMPLETE")
    print("==============================\n")

    return jsonify(results)

# =========================================================
if __name__ == "__main__":
    print("DUMP ANALYZER STARTED")
    app.run(debug=True)
