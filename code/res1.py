from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests, json, re
from collections import defaultdict

app = Flask(__name__, template_folder="templates")
CORS(app)

MODEL = "llama3:instruct"
AI_TIMEOUT = 120

session = requests.Session()
LAST_RESULT=None

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("res.html")

# ---------------- GROUP KEY ----------------
def group_key(line):
    parts=line.split("|")
    comp=parts[3].lower() if len(parts)>3 else "unknown"
    code=re.search(r'0x[0-9a-fA-F]+',line)
    code=code.group(0) if code else ""
    return f"{comp}|{code}"

# ---------------- SEVERITY ----------------
def get_severity(sample):
    s=sample.lower()

    if "failed" in s or "crash" in s:
        return "HIGH"

    if "not found" in s or "missing" in s:
        return "MEDIUM"

    return "LOW"

# ---------------- CONFIDENCE ----------------
def get_confidence(count):
    if count>50: return 0.95
    if count>20: return 0.85
    if count>5: return 0.75
    return 0.60

# ---------------- AI CALL ----------------
def call_ai(sample,context):

    prompt=f"""
You are a production support AI.

Cluster similar errors into SAME root cause.

Return JSON:
{{
"type":"",
"cause":"",
"fix":"",
"root_id":"short_id"
}}

Error:
{sample}

Context:
{context}
"""

    try:
        r=session.post(
            "http://localhost:11434/api/generate",
            json={"model":MODEL,"prompt":prompt,"stream":False},
            timeout=AI_TIMEOUT
        )

        data=r.json()
        text=data.get("response","")

        s=text.find("{")
        e=text.rfind("}")+1
        parsed=json.loads(text[s:e])

        return parsed

    except:
        return None

# ---------------- PROCESS ----------------
def process_group(key,occ,lines):

    idx=occ[0][0]
    sample=occ[0][1]
    count=len(occ)

    context="\n".join(lines[max(0,idx-3):idx+2])

    ai=call_ai(sample,context)

    if ai:
        t=ai.get("type","General Error")
        c=ai.get("cause","Unknown")
        f=ai.get("fix","Restart service")
        root=ai.get("root_id","GENERIC")
        source="ai"
    else:
        t="General Error"
        c="Configuration issue"
        f="Restart service"
        root="GENERIC"
        source="fallback"

    severity=get_severity(sample)
    confidence=get_confidence(count)

    return {
        "root":root,
        "type":t,
        "cause":c,
        "fix":f,
        "count":count,
        "sample":sample[:200],
        "severity":severity,
        "confidence":confidence,
        "source":source
    }

# ---------------- ANALYZE ----------------
def analyze_logs(text):

    lines=text.split("\n")

    errors=[(i,l) for i,l in enumerate(lines)
            if "error" in l.lower() or "failed" in l.lower()]

    groups=defaultdict(list)
    for idx,line in errors:
        groups[group_key(line)].append((idx,line))

    active=[]

    for k,occ in groups.items():
        active.append(process_group(k,occ,lines))

    # SMART MERGE BY ROOT
    merged={}
    for item in active:
        r=item["root"]
        if r not in merged:
            merged[r]=item
        else:
            merged[r]["count"]+=item["count"]

    active=list(merged.values())

    return {
        "total_errors":len(errors),
        "active_issues":active,
        "resolved_issues":[]
    }

# ---------------- ROUTE ----------------
@app.route("/analyze",methods=["POST"])
def analyze():
    global LAST_RESULT
    file=request.files["logfile"]
    text=file.read().decode("utf-8","ignore")
    LAST_RESULT=analyze_logs(text)
    return jsonify(LAST_RESULT)

# ---------------- CHAT ----------------
@app.route("/chat",methods=["POST"])
def chat():

    data=request.json
    q=data.get("q","")
    context=data.get("context","")

    if q.lower() in ["hi","hello"]:
        return jsonify({"answer":"Hi 👋 I'm your AI log assistant."})

    prompt=f"""
You are a log assistant.

User question:
{q}

Error:
{context}
"""

    r=session.post(
        "http://localhost:11434/api/generate",
        json={"model":MODEL,"prompt":prompt,"stream":False},
        timeout=120
    )

    return jsonify({"answer":r.json().get("response","")})

# ---------------- RUN ----------------
if __name__=="__main__":
    app.run(debug=True,use_reloader=False)
