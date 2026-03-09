# 🔐 CIPHER — Password Threat Intelligence System

A full-stack password auditing system with a real-time SOC dashboard frontend,
Python REST backend, and Java CLI tool.

---

## 📁 Project Structure

```
cipher-system/
│
├── backend/
│   └── server.py           ← Python REST API (runs on localhost:8080)
│
├── frontend/
│   └── index.html          ← SOC dashboard (open in browser)
│
├── java-cli/
│   └── src/
│       ├── PasswordChecker.java    ← Main entry point
│       ├── PasswordAnalyzer.java   ← Analysis engine
│       ├── AnalysisResult.java     ← Data model
│       └── TerminalRenderer.java   ← ANSI CLI output
│
├── start-backend.sh        ← Linux/Mac: start server
├── start-backend.bat       ← Windows:   start server
├── run-java-cli.sh         ← Linux/Mac: build & run CLI
└── run-java-cli.bat        ← Windows:   build & run CLI
```

---

## 🚀 Quick Start (Full Stack)

### Step 1 — Start the backend

**Linux / macOS:**
```bash
chmod +x start-backend.sh
./start-backend.sh
```

**Windows:**
```
Double-click start-backend.bat
```

You should see:
```
  🟢  Server running at http://localhost:8080
```

### Step 2 — Open the frontend

Open `frontend/index.html` in any modern browser.  
The SOC dashboard will connect to the backend automatically.

### Step 3 — Audit a password

Type any password in the input bar and click **▶ AUDIT** (or press Enter).

---

## 💻 Java CLI (Standalone)

The Java CLI works independently — no backend needed.

**Requirements:** Java JDK 11+ (not just JRE)
- Ubuntu/Debian: `sudo apt install default-jdk`
- macOS:         `brew install openjdk`
- Windows:       https://adoptium.net

**Build & run (Linux/macOS):**
```bash
chmod +x run-java-cli.sh
./run-java-cli.sh
```

**Batch mode (audit multiple passwords):**
```bash
./run-java-cli.sh "password123" "Tr0ub4dor&3" "X#9mK\$2vLq!nW8"
```

**Windows:**
```
Double-click run-java-cli.bat
```

---

## 🔍 What Gets Checked

| Module          | Details |
|-----------------|---------|
| Basic Rules     | Length (8/12/16), uppercase, lowercase, digits, symbols |
| Pattern Analysis| Repeated chars, sequential runs, keyboard walks, years, leet-speak |
| Entropy         | Shannon entropy in bits, character pool, total combinations |
| Crack Times     | Offline (10B guesses/sec GPU) and online (100/sec throttled) |
| Threat Sims     | Dictionary, rule-based, mask, hybrid, credential stuffing, GPU brute-force |
| DNA Fingerprint | Unique visual barcode generated from password structure |
| AI Analyst      | Personality reaction based on threat score (horrified → awestruck) |
| Gamification    | 12 achievement badges unlocked by password properties |

---

## 🌐 API Reference

```
GET http://localhost:8080/health
GET http://localhost:8080/analyze?password=YourPasswordHere
```

**Example response (truncated):**
```json
{
  "score": 82,
  "strength": "FORTRESS",
  "entropy": 95.2,
  "crack_offline": "centuries",
  "crack_online": "centuries",
  "checks": [...],
  "patterns": [...],
  "attacks": [...],
  "badges": [...],
  "ai": { "face": "😎", "mood": "IMPRESSED", "message": "..." },
  "dna": { "bars": [...], "hash": "A3F9..." }
}
```

---

## ⚙️ Requirements

| Component    | Requirement           |
|--------------|-----------------------|
| Backend      | Python 3.8+ (stdlib only, no pip needed) |
| Frontend     | Any modern browser (Chrome, Firefox, Edge, Safari) |
| Java CLI     | Java JDK 11+          |

---

## 🔒 Privacy

Passwords are **never** logged, stored, or sent anywhere outside your local machine.
The backend runs entirely on `localhost:8080`.
