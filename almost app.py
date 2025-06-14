import os
import traceback
import requests
from flask import Flask, request, render_template
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import asttokens

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ─────────────── Dummy ML Model ───────────────
samples = [
    "def add(a, b): return a + b",
    "print(x)",
    "def unsafe(): os.system('rm -rf /')",
    "def fail(): if True print('x')"
]
y = [0, 1, 1, 1]
X = [[len(s.splitlines()), len(s), int("os.system" in s)] for s in samples]
ml_model = Pipeline([("scaler", StandardScaler()), ("clf", RandomForestClassifier())])
ml_model.fit(X, y)

# ─────────────── Analysis Functions ───────────────
def detect_issues(code: str):
    issues = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if "os.system" in line:
            issues.append(f"[Line {i}] Shell command injection risk. Suggestion: Use `subprocess.run`")
        if line.strip().startswith("def") and '(' in line and ')' in line:
            fn_name = line.strip().split()[1].split("(")[0]
            if ":" not in line or len(line.strip()) < 10:
                issues.append(f"[Line {i}] Function `{fn_name}` may lack docstring or structure.")
    return issues

def get_metrics(code: str):
    score = mi_visit(code, True)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C"
    return round(score, 2), grade

def get_complexity(code: str):
    funcs = cc_visit(code)
    return [
        f"Function `{f.name}` → Score: {f.complexity}, Grade: " +
        ("A" if f.complexity <= 5 else "B" if f.complexity <= 10 else "C")
        for f in funcs
    ]

def ml_prediction(code: str):
    x = [[len(code.splitlines()), len(code), int("os.system" in code)]]
    return ml_model.predict(x)[0]

def ollama_suggestion(code: str):
    try:
        prompt = f"""You are an expert Python code reviewer.
Review the following code and provide:
- Bugs
- Suggestions
- Security risks
- Best practices\n\nCode:\n{code}
"""
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "deepseek-r1:1.5b", "prompt": prompt, "stream": False}
        )
        return response.json().get("response", "").strip()
    except Exception as e:
        return f"Ollama error: {e}"

def analyze_code_for_web(code: str):
    output = []

    try:
        asttokens.ASTTokens(code, parse=True)
    except SyntaxError as e:
        line = e.lineno
        msg = e.msg
        error_line = code.splitlines()[line - 1] if line <= len(code.splitlines()) else "<unavailable>"
        return f"❌ Syntax Error at Line {line}: {msg}<br>➡️ {error_line}"

    # Static issues
    issues = detect_issues(code)
    if issues:
        output.append("⚠️ Issues Detected:")
        output.extend(issues)
    else:
        output.append("✅ No static issues found.")

    # Maintainability
    score, grade = get_metrics(code)
    output.append(f"📈 Maintainability Index: {score} ({grade})")

    # Complexity
    complexity = get_complexity(code)
    if complexity:
        output.append("📊 Function Complexity:")
        output.extend(complexity)

    # ML Prediction
    prediction = ml_prediction(code)
    output.append("🤖 ML Prediction: " + ("❌ Potential bug detected" if prediction else "✅ Looks safe"))

    # Runtime Check
    try:
        exec(code, {})
        output.append("⚙ Runtime Check: ✅ No runtime errors")
    except Exception as e:
        tb = traceback.extract_tb(e.__traceback__)
        lineno = tb[-1].lineno if tb else -1
        error_line = code.splitlines()[lineno - 1] if lineno != -1 else "<Unavailable>"
        output.append(f"⚙ Runtime Error on Line {lineno}: {e}")
        output.append(f"➡️ {error_line}")

    # AI Suggestion
    output.append("🧠 AI Suggestions (Ollama):")
    output.append(ollama_suggestion(code))

    return "<br>".join(output)

# ─────────────── Routes ───────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'pythonFile' not in request.files:
        return "❌ No file part in the request.", 400

    file = request.files['pythonFile']

    if file.filename == '':
        return "❌ No selected file.", 400

    if not file.filename.endswith('.py'):
        return "❌ Please upload a valid Python (.py) file.", 400

    code = file.read().decode('utf-8')

    try:
        result = analyze_code_for_web(code)
        return result
    except Exception as e:
        return f"❌ Unexpected Error: {e}", 500

# ─────────────── Run Server ───────────────
if __name__ == '__main__':
    app.run(debug=True)
