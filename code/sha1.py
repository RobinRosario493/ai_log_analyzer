from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import re
from collections import defaultdict
from ai_engine import analyze_patterns_with_ai
import requests

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:8b"

# ---------------- DB ----------------
def init_db():
    conn = sqlite3.connect("chat_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_message TEXT,
            ai_reply TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

LAST_RESULTS = []

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("sha1.html")

# ---------------- NORMALIZE ----------------
def normalize(line):
    line = line.lower()
    line = re.sub(r'\d+', 'X', line)
    line = re.sub(r'0x[0-9a-fA-F]+', 'HEX', line)
    return line.strip()

# ---------------- RECOVERY DETECTION ----------------
def is_recovery_line(line):
    words = [
        "success","restored","recovered",
        "connected","retry succeeded","mounted successfully"
    ]
    return any(w in line.lower() for w in words)

# ---------------- ANALYSIS PER FILE ----------------
def analyze_errors_only(log_text, filename):

    lines = log_text.split("\n")
    groups = defaultdict(list)
    total_errors = 0

    for i,line in enumerate(lines):
        if any(x in line.lower() for x in ["error","failed","exception","fatal"]):
            total_errors += 1
            key = normalize(line)
            groups[key].append((i,line))

    if total_errors == 0:
        return {"file":filename,"total_errors":0,"analysis":[]}

    patterns = list(groups.items())

    MAX_AI_PATTERNS = 40
    ai_patterns = patterns[:MAX_AI_PATTERNS]
    remaining_patterns = patterns[MAX_AI_PATTERNS:]

    cards = []
    chunk_size = 3

    # ---------- AI classification ----------
    for i in range(0,len(ai_patterns),chunk_size):

        chunk = ai_patterns[i:i+chunk_size]
        samples = [occ[0][1] for _,occ in chunk]

        print(f"{filename} → AI batch {i//chunk_size+1}")

        ai_results = analyze_patterns_with_ai(samples)

        for idx,(pattern,occ) in enumerate(chunk):

            count = len(occ)
            first_index = occ[0][0]
            sample = occ[0][1]

            status = "Active"
            for l in lines[first_index:first_index+10]:
                if is_recovery_line(l):
                    status="Resolved"
                    break

            if idx < len(ai_results):
                r = ai_results[idx]
                t = r["type"]
                c = r["cause"]
                f = r["fix"]
                severity = r["severity"]
            else:
                t="Unknown Error"
                c="AI missing"
                f="Manual check"
                severity="Medium"

            if status=="Resolved":
                c=""
                f=""

            cards.append({
                "file":filename,
                "error_line":sample,
                "type":t,
                "cause":c,
                "fix":f,
                "count":count,
                "status":status,
                "severity":severity
            })

    # ---------- remaining patterns reuse ----------
    for pattern,occ in remaining_patterns:

        sample = occ[0][1]
        count = len(occ)

        matched = None
        for card in cards:
            if card["type"].lower() in sample.lower():
                matched = card
                break

        if matched:
            t = matched["type"]
            c = matched["cause"]
            f = matched["fix"]
            severity = matched["severity"]
        else:
            t="General System Error"
            c="Similar recurring issue"
            f="Check related service"
            severity="Medium"

        cards.append({
            "file":filename,
            "error_line":sample,
            "type":t,
            "cause":c,
            "fix":f,
            "count":count,
            "status":"Active",
            "severity":severity
        })

    return {
        "file":filename,
        "total_errors":total_errors,
        "analysis":cards
    }

# ---------------- ANALYZE ROUTE ----------------
@app.route("/analyze", methods=["POST"])
def analyze():

    global LAST_RESULTS
    LAST_RESULTS = []

    files = request.files.getlist("logfile")

    # remove duplicates
    unique=[]
    seen=set()

    for f in files:
        f.seek(0,2)
        size=f.tell()
        f.seek(0)
        key=(f.filename,size)

        if key not in seen:
            seen.add(key)
            unique.append(f)

    files=unique

    for file in files:
        text=file.read().decode("utf-8","ignore")
        result=analyze_errors_only(text,file.filename)
        LAST_RESULTS.append(result)

    return jsonify({"files":LAST_RESULTS})

# ---------------- ASK AI ----------------
@app.route("/ask_ai", methods=["POST"])
def ask_ai():

    data=request.json
    error=data.get("error","")

    prompt=f"""
Explain this system error clearly and give fix:

{error}
"""

    r=requests.post(
        "http://localhost:11434/api/generate",
        json={"model":MODEL,"prompt":prompt,"stream":False},
        timeout=60
    )

    return jsonify({"answer":r.json().get("response","")})

# ---------------- CHAT ----------------
@app.route("/chat", methods=["POST"])
def chat():

    data=request.json
    msg=data.get("message","")

    summary=str(LAST_RESULTS)[:2000]

    prompt=f"""
You are system support AI.

Logs summary:
{summary}

User:
{msg}
"""

    r=requests.post(
        "http://localhost:11434/api/generate",
        json={"model":MODEL,"prompt":prompt,"stream":False},
        timeout=60
    )

    reply=r.json().get("response","")

    conn=sqlite3.connect("chat_history.db")
    cur=conn.cursor()
    cur.execute(
        "INSERT INTO chat_messages (user_message,ai_reply) VALUES (?,?)",
        (msg,reply)
    )
    conn.commit()
    conn.close()

    return jsonify({"reply":reply})

# ---------------- RUN ----------------

if __name__ == "__main__":
    print("SERVER STARTED")
    app.run(host="127.0.0.1",port=5000,debug=True)
