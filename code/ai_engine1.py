import requests
import json

def safe_json_extract(text):
    try:
        s = text.find("[")
        e = text.rfind("]")+1
        return json.loads(text[s:e])
    except:
        return []

def analyze_patterns_with_ai(samples):

    prompt = """
You are a senior production support engineer.

Create REAL incident names.
Not generic categories.

Return JSON array only.

Format:
[
 {"type":"","cause":"","fix":"","severity":""}
]

Errors:
"""

    for s in samples:
        prompt += "\n- " + s

    r = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model":"llama3:8b",
            "prompt":prompt,
            "stream":False,
            "options":{
                "temperature":0,
                "num_predict":250
            }
        },
        timeout=120
    )

    txt = r.json().get("response","")
    return safe_json_extract(txt)
