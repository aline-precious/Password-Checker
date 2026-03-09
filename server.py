#!/usr/bin/env python3
"""
CIPHER — Password Threat Intelligence Backend
Run: python3 server.py
API available at http://localhost:8080
"""

import json
import re
import math
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs

# ── Common passwords ────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password","password1","password123","123456","123456789","12345678","12345",
    "1234567","1234567890","qwerty","abc123","monkey","letmein","dragon","111111",
    "baseball","iloveyou","trustno1","sunshine","master","welcome","shadow",
    "ashley","football","jesus","michael","ninja","mustang","jessica","charlie",
    "donald","password2","qwerty123","admin","root","pass","test","guest","login",
    "hello","123","000000","654321","1q2w3e","superman","batman","access","555555",
    "lovely","666666","princess","starwars","solo","passw0rd","p@ssword","hunter2",
    "696969","hottie","loveme","zaq1zaq1","password!","abc1234","qazwsx","1qaz2wsx",
}

DICTIONARY_WORDS = {
    "password","admin","user","login","welcome","hello","test","demo","default",
    "system","server","manager","computer","internet","network","security","access",
    "master","secret","private","public","super","root","home","work","office",
    "house","family","friend","love","life","death","god","money","power","time",
    "summer","winter","spring","autumn","monday","january","february","march",
    "abc","xyz","qwerty","dragon","monkey","shadow","sunshine","princess","baseball",
}

# ── Regex patterns ──────────────────────────────────────────────────────────────
RE_UPPER        = re.compile(r'[A-Z]')
RE_LOWER        = re.compile(r'[a-z]')
RE_DIGIT        = re.compile(r'\d')
RE_SPECIAL      = re.compile(r'[^A-Za-z0-9]')
RE_REPEATED     = re.compile(r'(.)\1{2,}')
RE_SEQ_NUM      = re.compile(r'(?:0123|1234|2345|3456|4567|5678|6789|7890)')
RE_SEQ_ALPHA    = re.compile(r'(?i)(?:abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)')
RE_KBD_WALK     = re.compile(r'(?i)(?:qwer|wert|erty|rtyu|tyui|yuio|uiop|asdf|sdfg|dfgh|fghj|ghjk|hjkl|zxcv|xcvb|cvbn|vbnm|wasd)')
RE_ALL_DIGITS   = re.compile(r'^\d+$')
RE_ALL_ALPHA    = re.compile(r'^[A-Za-z]+$')
RE_LEET         = re.compile(r'(?i)(?:p[a@]ssw[o0]rd|[a@]dmin|l[o0]gin|s[e3]cur[e3]|w[e3]lc[o0]m[e3])')
RE_YEAR         = re.compile(r'(?:19|20)\d{2}')
RE_RULE_BASED   = re.compile(r'^(?:[a-zA-Z]+\d{1,4}[!@#$]?|[A-Z][a-z]+\d{1,4})$')
RE_MASK_SIMPLE  = re.compile(r'^[a-z]{4,8}$')
RE_CAP_WORD_NUM = re.compile(r'^[A-Z][a-z]{3,7}\d{1,2}$')

# ─────────────────────────────────────────────────────────────────────────────
#  ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def get_charset_pool(pw: str) -> int:
    pool = 0
    if RE_LOWER.search(pw):   pool += 26
    if RE_UPPER.search(pw):   pool += 26
    if RE_DIGIT.search(pw):   pool += 10
    if RE_SPECIAL.search(pw): pool += 32
    return pool or 10

def get_entropy(pw: str) -> float:
    pool = get_charset_pool(pw)
    return len(pw) * math.log2(pool)

def format_time(seconds: float) -> str:
    if seconds < 1:             return "< 1 second"
    if seconds < 60:            return f"{seconds:.0f} seconds"
    if seconds < 3600:          return f"{seconds/60:.0f} minutes"
    if seconds < 86400:         return f"{seconds/3600:.0f} hours"
    if seconds < 2_592_000:     return f"{seconds/86400:.0f} days"
    if seconds < 31_536_000:    return f"{seconds/2_592_000:.0f} months"
    if seconds < 3_153_600_000: return f"{seconds/31_536_000:.0f} years"
    return "centuries"

def check_basic_rules(pw: str) -> list:
    checks = []
    n = len(pw)
    checks.append({"id":"len8",    "label":"Length ≥ 8",          "passed": n >= 8,   "detail": f"{n} chars" if n < 8  else "Pass"})
    checks.append({"id":"len12",   "label":"Length ≥ 12",         "passed": n >= 12,  "detail": f"Only {n} chars" if n < 12 else "Pass"})
    checks.append({"id":"len16",   "label":"Length ≥ 16",         "passed": n >= 16,  "detail": f"Only {n} chars" if n < 16 else "Pass"})
    checks.append({"id":"upper",   "label":"Uppercase (A-Z)",     "passed": bool(RE_UPPER.search(pw)),   "detail": "Add uppercase letters"})
    checks.append({"id":"lower",   "label":"Lowercase (a-z)",     "passed": bool(RE_LOWER.search(pw)),   "detail": "Add lowercase letters"})
    checks.append({"id":"digit",   "label":"Contains digit",      "passed": bool(RE_DIGIT.search(pw)),   "detail": "Add 0–9 digits"})
    checks.append({"id":"special", "label":"Symbol !@#$%^&*",     "passed": bool(RE_SPECIAL.search(pw)), "detail": "Add special characters"})
    checks.append({"id":"notall_digits","label":"Not all digits",  "passed": not bool(RE_ALL_DIGITS.match(pw)), "detail": "Mix in letters"})
    checks.append({"id":"notall_alpha", "label":"Not all letters", "passed": not bool(RE_ALL_ALPHA.match(pw)),  "detail": "Mix in digits/symbols"})
    return checks

def check_patterns(pw: str) -> list:
    lower = pw.lower()
    patterns = []

    is_common = lower in COMMON_PASSWORDS
    patterns.append({"id":"nocommon",  "label":"Not in breach list",     "passed": not is_common,
                      "detail": "⚠ Found in top breach database!" if is_common else "Not in common list"})

    has_dict = any(w in lower for w in DICTIONARY_WORDS if len(w) >= 4)
    patterns.append({"id":"nodict",    "label":"No dictionary base word", "passed": not has_dict,
                      "detail": "Contains a common dictionary word" if has_dict else "OK"})

    has_leet = bool(RE_LEET.search(pw))
    patterns.append({"id":"noleet",    "label":"No leet-speak variant",   "passed": not has_leet,
                      "detail": "Leet-speak of 'password'/'admin' found" if has_leet else "OK"})

    has_rep = bool(RE_REPEATED.search(pw))
    patterns.append({"id":"norepeat",  "label":"No repeated chars (aaa)", "passed": not has_rep,
                      "detail": "3+ consecutive identical chars found" if has_rep else "OK"})

    has_snum = bool(RE_SEQ_NUM.search(pw))
    patterns.append({"id":"noseqnum",  "label":"No sequential nums (1234)","passed": not has_snum,
                      "detail": "Sequential number run detected" if has_snum else "OK"})

    has_salpha = bool(RE_SEQ_ALPHA.search(pw))
    patterns.append({"id":"noseqalph", "label":"No sequential abc",       "passed": not has_salpha,
                      "detail": "Sequential letter run detected" if has_salpha else "OK"})

    has_kbd = bool(RE_KBD_WALK.search(pw))
    patterns.append({"id":"nokbd",     "label":"No keyboard walk (qwer)", "passed": not has_kbd,
                      "detail": "Keyboard walk pattern detected" if has_kbd else "OK"})

    has_year = bool(RE_YEAR.search(pw))
    patterns.append({"id":"noyear",    "label":"No embedded year",        "passed": not has_year,
                      "detail": "Contains a 4-digit year" if has_year else "OK"})

    return patterns

def simulate_attacks(pw: str) -> list:
    lower = pw.lower()
    pool = get_charset_pool(pw)
    combos = pool ** len(pw)
    offline_time = combos / 1e10

    attacks = []

    # Dictionary
    dict_vuln = lower in COMMON_PASSWORDS
    attacks.append({"id":"dict",   "name":"Dictionary Attack",
                     "icon":"📖",  "vulnerable": dict_vuln,
                     "detail": "VULNERABLE — exact match in wordlist" if dict_vuln else "Resistant"})

    # Rule-based
    rule_vuln = bool(RE_RULE_BASED.match(pw)) and len(pw) < 12
    attacks.append({"id":"rule",   "name":"Rule-Based (word+digit)",
                     "icon":"⚙️",  "vulnerable": rule_vuln,
                     "detail": "VULNERABLE — trivial word+number pattern" if rule_vuln else "Resistant"})

    # Mask
    mask_vuln = (bool(RE_ALL_DIGITS.match(pw)) or bool(RE_MASK_SIMPLE.match(pw)) or
                 bool(RE_CAP_WORD_NUM.match(pw)) or len(pw) < 7)
    attacks.append({"id":"mask",   "name":"Mask Brute-Force",
                     "icon":"🎭",  "vulnerable": mask_vuln,
                     "detail": "VULNERABLE — matches simple brute-force mask" if mask_vuln else "Resistant"})

    # Hybrid
    hybrid_vuln = any(lower.startswith(w) and len(pw) - len(w) <= 4 for w in DICTIONARY_WORDS)
    attacks.append({"id":"hybrid", "name":"Hybrid Dict+Suffix",
                     "icon":"🧬",  "vulnerable": hybrid_vuln,
                     "detail": "VULNERABLE — dictionary word with short suffix" if hybrid_vuln else "Resistant"})

    # Credential stuffing
    stuff_vuln = lower in COMMON_PASSWORDS
    attacks.append({"id":"stuff",  "name":"Credential Stuffing",
                     "icon":"🗄️",  "vulnerable": stuff_vuln,
                     "detail": "VULNERABLE — found in breach database" if stuff_vuln else "Not in simulated breach list"})

    # GPU brute force
    gpu_vuln = offline_time < 3600
    attacks.append({"id":"brute",  "name":"GPU Brute-Force",
                     "icon":"💻",  "vulnerable": gpu_vuln,
                     "detail": f"VULNERABLE — crackable in {format_time(offline_time)}" if gpu_vuln else "Would take too long"})

    return attacks

def compute_score(pw: str, checks: list, patterns: list, attacks: list) -> int:
    score = 0
    score += min(len(pw) * 2, 30)
    if RE_LOWER.search(pw):   score += 5
    if RE_UPPER.search(pw):   score += 5
    if RE_DIGIT.search(pw):   score += 5
    if RE_SPECIAL.search(pw): score += 10

    entropy = get_entropy(pw)
    if entropy >= 80:   score += 20
    elif entropy >= 60: score += 12
    elif entropy >= 40: score += 6

    failed_checks   = sum(1 for c in checks if not c["passed"])
    failed_patterns = sum(1 for p in patterns if not p["passed"])
    failed_attacks  = sum(1 for a in attacks if a["vulnerable"])

    score -= failed_checks   * 3
    score -= failed_patterns * 5
    score -= failed_attacks  * 8

    return max(0, min(100, score))

def compute_badges(pw: str, score: int, checks: list, patterns: list) -> list:
    earned = []
    check_map  = {c["id"]: c["passed"] for c in checks}
    pattern_map = {p["id"]: p["passed"] for p in patterns}

    badges = [
        ("len8",    "📏", "8+ CHARS",     len(pw) >= 8),
        ("len16",   "📐", "16+ CHARS",    len(pw) >= 16),
        ("mixed",   "🔤", "MIXED CASE",   bool(RE_UPPER.search(pw)) and bool(RE_LOWER.search(pw))),
        ("digits",  "🔢", "HAS DIGITS",   bool(RE_DIGIT.search(pw))),
        ("special", "💥", "HAS SYMBOLS",  bool(RE_SPECIAL.search(pw))),
        ("entropy", "⚡", "HIGH ENTROPY", get_entropy(pw) >= 60),
        ("nodict",  "📚", "NO DICT WORD", pattern_map.get("nodict", False)),
        ("complex", "🏗", "COMPLEX",      sum(1 for c in checks if not c["passed"]) <= 2),
        ("fortress","🏰", "FORTRESS",     score >= 70),
        ("elite",   "💎", "ELITE",        score >= 85),
        ("unique",  "🦄", "UNIQUE",       len(pw) >= 14 and bool(RE_SPECIAL.search(pw))),
        ("godmode", "👑", "GOD MODE",     score >= 95),
    ]

    for bid, icon, name, cond in badges:
        earned.append({"id": bid, "icon": icon, "name": name, "earned": cond})

    return earned

def get_ai_reaction(score: int) -> dict:
    if score >= 95:
        return {"face":"🤩","mood":"AWESTRUCK",
                "message":"EXCEPTIONAL. My threat models flag this as virtually uncrackable. Even nation-state adversaries with unlimited GPU resources would need centuries. This is textbook fortress-grade security."}
    if score >= 80:
        return {"face":"😎","mood":"IMPRESSED",
                "message":"STRONG RESISTANCE DETECTED. This password would repel automated attacks and force any adversary toward social engineering instead. Well architected across entropy, complexity, and pattern avoidance."}
    if score >= 65:
        return {"face":"😏","mood":"SATISFIED",
                "message":"SOLID. Above average threat resistance. Survivable against most commodity attack tools. A determined adversary with targeted wordlists might still find a vector — consider increasing length."}
    if score >= 45:
        return {"face":"🤔","mood":"CONCERNED",
                "message":"MODERATE RISK. Several attack vectors remain viable. This would hold against casual attackers but not scripted rule-based tools. Significant improvements recommended before use on sensitive accounts."}
    if score >= 25:
        return {"face":"😰","mood":"NERVOUS",
                "message":"HIGH RISK FLAGGED. Multiple active vulnerabilities detected. Rule-based and hybrid attacks have strong probability of success. This password offers minimal real-world protection."}
    return {"face":"😱","mood":"HORRIFIED",
            "message":"CRITICAL VULNERABILITY. This password would be compromised within seconds on a modern GPU rig. It matches known breach databases and/or trivial attack patterns. Do not use this under any circumstances."}

def generate_dna_fingerprint(pw: str) -> dict:
    """Generate deterministic visual data for the DNA fingerprint chart."""
    bars = []
    colors = ['#00d4ff','#00ff9d','#ff3366','#ffaa00','#cc44ff']
    num_bars = min(len(pw) * 3, 80)

    seed = 0
    for ch in pw:
        seed = (seed * 31 + ord(ch)) & 0xFFFFFFFF

    for i in range(num_bars):
        char_idx = (i // 2) % len(pw)
        char_code = ord(pw[char_idx])
        h = 10 + ((char_code * (i + 1) * 7) % 90)
        col = colors[char_code % len(colors)]
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        alpha = 0.4 + (char_code % 60) / 100
        bars.append({"height": h, "color": col, "alpha": round(alpha, 2)})

    # Hash
    hash_str = ""
    for i in range(16):
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        hash_str += format((seed * (i+1)) & 0xFF, '02x')

    return {"bars": bars, "hash": hash_str.upper()}

def analyze_password(pw: str) -> dict:
    checks   = check_basic_rules(pw)
    patterns = check_patterns(pw)
    attacks  = simulate_attacks(pw)
    score    = compute_score(pw, checks, patterns, attacks)
    badges   = compute_badges(pw, score, checks, patterns)
    ai       = get_ai_reaction(score)
    dna      = generate_dna_fingerprint(pw)
    entropy  = get_entropy(pw)
    pool     = get_charset_pool(pw)
    combos   = pool ** len(pw)
    offline  = combos / 1e10
    online   = combos / 100

    strength_labels = {
        (80, 101): "FORTRESS",
        (60, 80):  "SECURE",
        (35, 60):  "VULNERABLE",
        (0,  35):  "CRITICAL",
    }
    strength = next(v for (lo, hi), v in strength_labels.items() if lo <= score < hi)

    return {
        "score":         score,
        "strength":      strength,
        "entropy":       round(entropy, 2),
        "pool":          pool,
        "length":        len(pw),
        "combinations":  f"{combos:.2e}",
        "crack_offline": format_time(offline),
        "crack_online":  format_time(online),
        "checks":        checks,
        "patterns":      patterns,
        "attacks":       attacks,
        "badges":        badges,
        "ai":            ai,
        "dna":           dna,
    }

# ─────────────────────────────────────────────────────────────────────────────
#  HTTP SERVER
# ─────────────────────────────────────────────────────────────────────────────

class CipherHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"  [{self.address_string()}] {format % args}")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/analyze":
            params = parse_qs(parsed.query)
            pw = params.get("password", [""])[0]

            if not pw:
                self._json_error(400, "Missing 'password' query parameter")
                return

            result = analyze_password(pw)
            self._json_ok(result)

        elif parsed.path == "/health":
            self._json_ok({"status": "online", "engine": "CIPHER v1.0"})

        else:
            self._json_error(404, "Not found")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_ok(self, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _json_error(self, code, msg):
        body = json.dumps({"error": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    PORT = 8080
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║   CIPHER Threat Intelligence Backend    ║")
    print("  ╚══════════════════════════════════════════╝")
    print(f"  🟢  Server running at http://localhost:{PORT}")
    print(f"  🔍  API: http://localhost:{PORT}/analyze?password=YourPass")
    print(f"  ❤️   Health: http://localhost:{PORT}/health")
    print("  Press Ctrl+C to stop.\n")

    with socketserver.TCPServer(("", PORT), CipherHandler) as httpd:
        httpd.allow_reuse_address = True
        httpd.serve_forever()
