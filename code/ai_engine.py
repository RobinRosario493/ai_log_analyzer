import requests
import json

# ---------------- SAFE JSON PARSE ----------------
def safe_json_extract(text):
    try:
        start = text.find('[')
        end = text.rfind(']') + 1

        if start == -1 or end == -1:
            print("JSON not found in response")
            return []

        json_text = text[start:end]
        data = json.loads(json_text)

        results = []

        for item in data:
            results.append({
                "type": item.get("type") or "Unknown",
                "cause": item.get("cause") or "Unknown",
                "fix": item.get("fix") or "Manual investigation required",
                "severity": item.get("severity") or "Medium"
            })

        return results

    except Exception as e:
        print("JSON PARSE ERROR:", e)
        print("Raw AI response:", text)
        return []

# ---------------- AI ANALYSIS ----------------
def analyze_patterns_with_ai(samples):

    prompt = """
You are a senior production support engineer.

For each log error, create a SPECIFIC descriptive error name.
Do NOT return generic categories like:
File, Service, Registry, Network.

Instead generate real incident names like:
"Audio Driver Initialization Failure"
"Registry Permission Corruption"
"Database Connection Timeout"
"Kernel Module Load Failure"

Also provide:
- root technical cause
- actionable fix
- severity (Critical, High, Medium, Low)

Return ONLY valid JSON array.

Format:
[
 {"type":"","cause":"","fix":"","severity":""}
]

Errors:
"""



    for s in samples:
        prompt += f"\n- {s}"

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3:8b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "top_p": 0.1,
                    "num_predict": 300
                }
            },
            timeout=180
        )

        data = response.json()
        ai_text = data.get("response", "")

        return safe_json_extract(ai_text)

    except Exception as e:
        print("AI REQUEST ERROR:", e)
        return []
