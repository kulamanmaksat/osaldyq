import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import re

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py', 'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_code(code):
    vulnerabilities = []
    total_score = 0
    checks = {
        'SQL Injection': {
            'pattern': r"""
                (?x)                                  # Включаем verbose режим
                (?:
                    (?:execute|executemany)\s*\(     # SQL execute методы
                    [^)]*                            # Любые символы до закрывающей скобки
                    (?:"|')                          # Открывающая кавычка
                    .*?(?:SELECT|INSERT|UPDATE|DELETE)# SQL команды
                    .*?(?:"|')                       # Закрывающая кавычка
                    [^)]*\)                          # До конца вызова
                    |
                    (?:SELECT|INSERT|UPDATE|DELETE)\s+# Прямые SQL запросы
                    .*?(?:\+|format|%)               # Конкатенация или форматирование
                )
            """,
            'message': "SQL-инъекция табылды - параметрленген сұраныстарды қолданыңыз",
            'score': 85,
            'safe_pattern': r'\?\s*,|\%s\s*,'
        },
        'XSS': {
            'pattern': r"""
                (?x)
                (?:
                    (?:document\.write|innerHTML|outerHTML|insertAdjacentHTML)
                    \s*
                    =?
                    \s*
                    (?:\()?
                    [^);]*?
                    (?:\+|concat|join|template|\$\{)
                    .*?
                    (?:\)|;)?
                    |
                    <script[^>]*>
                    .*?
                    (?:\+|concat|join|template|\$\{)
                )
            """,
            'message': "XSS-осалдық табылды - контентті қауіпсіз енгізу әдістерін қолданыңыз",
            'score': 80,
            'safe_pattern': r'textContent|innerText|escape|sanitize|DOMPurify'
        },
        'Command Injection': {
            'pattern': r"""
                (?x)
                (?:
                    (?:os\.system|subprocess\.call|exec|eval|execfile)
                    \s*
                    \(
                    .*?
                    (?:\+|format|join|template|\$\{)
                    |
                    `.*?(?:\$\{|\$\()`
                )
            """,
            'message': "Команда инъекциясы табылды - shell=False параметрімен subprocess.run қолданыңыз",
            'score': 90,
            'safe_pattern': r'subprocess\.run\([^,]+,\s*shell\s*=\s*False\)'
        },
        'Path Traversal': {
            'pattern': r"""
                (?x)
                (?:
                    (?:open|file|read|write)
                    \s*
                    \(
                    .*?
                    (?:\+|format|join|template|\$\{)
                    |
                    \.\.(?:/|\\)
                )
            """,
            'message': "Path traversal осалдығы табылды - os.path.basename қолданыңыз",
            'score': 75,
            'safe_pattern': r'os\.path\.(?:basename|abspath|realpath)'
        },
        'Hardcoded Credentials': {
            'pattern': r"""
                (?x)
                (?:
                    (?:password|api_key|secret|token|key)
                    \s*
                    =
                    \s*
                    (?:"|')
                    [^"']+
                    (?:"|')
                    |
                    (?:Authorization|Bearer)\s*:\s*(?:"|')[^"']+(?:"|')
                )
            """,
            'message': "Қатты кодталған тіркелгі деректері табылды - орта айнымалыларын қолданыңыз",
            'score': 70,
            'safe_pattern': r'os\.environ\.get|dotenv'
        },
        'Unsafe Deserialization': {
            'pattern': r"""
                (?x)
                (?:
                    pickle\.(?:loads?|dumps?)
                    |
                    yaml\.load(?!\s*\(.*?SafeLoader\))
                    |
                    marshal\.loads?
                    |
                    unserialize
                )
            """,
            'message': "Қауіпсіз емес десериализация табылды - json немесе yaml.safe_load қолданыңыз",
            'score': 85,
            'safe_pattern': r'json\.(?:loads?|dumps?)|yaml\.safe_load'
        },
        'Weak Cryptography': {
            'pattern': r"""
                (?x)
                (?:
                    (?:DES|RC4|MD5|SHA1)
                    |
                    hashlib\.(?:md5|sha1)
                    |
                    random\.(?:random|randint)
                    |
                    math\.random
                )
            """,
            'message': "Ескірген криптографиялық әдістер табылды - заманауи алгоритмдерді қолданыңыз",
            'score': 80,
            'safe_pattern': r'hashlib\.(?:sha256|sha512)|secrets\.|cryptography\.'
        },
        'Race Condition': {
            'pattern': r"""
                (?x)
                (?:
                    transaction|lock|mutex
                    |
                    while\s+True
                    |
                    while\s*\(\s*1\s*\)
                    |
                    (?:time\.)?sleep\s*\(
                )
            """,
            'message': "Ықтимал race condition - блоктау немесе транзакцияларды қолданыңыз",
            'score': 70,
            'safe_pattern': r'with\s+(?:transaction|lock|mutex)|atomic|synchronized'
        },
        'Buffer Overflow': {
            'pattern': r"""
                (?x)
                (?:
                    create_string_buffer
                    |
                    ctypes\.create_string_buffer
                    |
                    strcpy
                    |
                    strcat
                    |
                    gets
                    |
                    scanf
                )
            """,
            'message': "Ықтимал буфер толып кетуі - деректер өлшемін тексеріңіз",
            'score': 85,
            'safe_pattern': r'len\s*\(.*?\)\s*<|bound|limit'
        },
        'Insecure Input Validation': {
            'pattern': r"""
                (?x)
                (?:
                    input\s*\(
                    |
                    raw_input\s*\(
                    |
                    \.get\s*\(\s*(?:"|')[^"']+(?:"|')\s*\)
                )
            """,
            'message': "Қауіпсіз емес кіріс деректерді тексеру - түрлерді тексеру және санитизацияны қолданыңыз",
            'score': 75,
            'safe_pattern': r'validate|sanitize|escape|is_valid|clean'
        }
    }

    total_checks = len(checks)
    found_vulnerabilities = 0

    for vuln_type, check in checks.items():
        if re.search(check['pattern'], code, re.IGNORECASE | re.MULTILINE | re.VERBOSE):
            if 'safe_pattern' in check and re.search(check['safe_pattern'], code, re.IGNORECASE | re.MULTILINE):
                continue
            vulnerabilities.append(check['message'])
            total_score += check['score']
            found_vulnerabilities += 1

    if found_vulnerabilities > 0:
        average_score = total_score / found_vulnerabilities
        risk_level = "Жоғары" if average_score > 80 else "Орташа" if average_score > 60 else "Төмен"
    else:
        average_score = 0
        risk_level = "Төмен"

    return {
        "score": round(average_score),
        "vulnerabilities": vulnerabilities,
        "risk": risk_level,
        "total_checks": total_checks,
        "found_vulnerabilities": found_vulnerabilities,
        "false_positive_warning": found_vulnerabilities > 0 and all(
            re.search(check.get('safe_pattern', '$^'), code, re.IGNORECASE | re.MULTILINE)
            for check in checks.values()
        )
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    code = data.get('code', '')
    result = analyze_code(code)
    return jsonify(result)

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Файл жүктелмеді'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Файл таңдалмады'})
    
    code = file.read().decode('utf-8')
    result = analyze_code(code)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5001) 