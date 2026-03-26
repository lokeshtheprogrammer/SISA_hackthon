# SISA_hackthon
# 🚀 AI Secure Data Intelligence Platform (ASDIP v6.0)

Welcome to ASDIP—an intelligent, modular platform built to solve one of the biggest headaches in modern security engineering: parsing massive walls of unstructured text and logs to silently hunt down data leaks, secrets, and targeted attacks.

Think of this as a lightweight, lightning-fast miniature SIEM (Security Information and Event Management) system. It acts as an AI Gateway, Data Scanner, Log Analyzer, and Risk Engine—all bundled into a single deployment.

---

## 💡 What does it actually do?
Modern applications dump massive amounts of unstructured data. If an engineer accidentally leaves `password=123` in a debug trace, or a hacker starts brute-forcing an endpoint, finding those needles in the log-haystack is notoriously difficult.

ASDIP accepts any text-based input (drag-and-dropped `.log` files, raw text, PDFs, SQL payloads, or even real-time API streams), normalizes it, and runs it through a 7-stage detection pipeline. If it finds a critical leak, it mathematically scores the risk, instantly masks the secret to prevent it from saving to the database, and uses an AI Engine to output a human-readable remediation summary.

---

## 🛠 Features & Capabilities

 Multi-Format Ingestion: Drag and drop `.txt`, `.log`, `.pdf`, or raw code directly into the UI.
 Real-Time Live Streaming (SSE): Actively tails backend network traffic and application logs using an asynchronous Server-Sent Events endpoint. Risk levels are color-coded live as data flows in.
 Correlated Threat Detection: Doesn't just scan single lines. The engine keeps states in memory to look ahead/behind—allowing it to actively detect complex behaviors like Brute Force credential stuffing or `Fail -> Fail -> Success` patterns.
 Log Clustering (Drain3): Uses the `drain3` template miner to rip apart chaotic log text, separating the static templates from actual variables, making anomaly detection exponentially faster.
 Dynamic AI Remediation: Generates a strict, actionable JSON map detailing the Issue, Impact, Root Cause, and Fix for every single vulnerability found.
 Rate-Limited Batch Processing: An enterprise-ready `/analyze/batch` API protected by `slowapi` that allows for massive batched payload processing asynchronously.

---

## 🧠 Under the Hood (The 7-Layer Architecture)

When a 50MB log file is dropped into the system, here is exactly what happens in milliseconds:

1. The Input Router & Chunker: To prevent the server RAM from flatlining, the file is run through an async generator that yields the text in 5000-character chunks.
2. The Parser Engine: The chunks hit the `Drain3` cluster mapper which organizes the text into parsable tree nodes.
3. The Detection Layer: A deeply tuned Regex engine hunts down `sk-` Open AI keys, JWT bearer tokens, raw passwords, AWS credentials, and stack traces.
4. The Correlation Engine: The engine looks specifically for time-based attack sequences (e.g., 5 failed log-in attempts from the same IP within 20 lines) and flags them.
5. The Risk Engine: A custom scoring algorithm assigns weights (`password = +6`, `Sequence Attack = +5`) and maps the final sum to `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk tiers.
6. The Masking & Policy Engine: If a critical secret is found, the data is automatically redacted (`[MASKED]`) in memory before it's allowed to persist to the database.
7. The AI engine: The parsed metadata is handed directly to an LLM interface (or the ultra-fast Python Fallback Engine) to generate the final Root-Cause analysis payload.

---

## 💻 Tech Stack & Engineering Choices

I specifically chose technologies that mimic real-world Enterprise environments:

 Backend: `FastAPI` (Python). Chosen for its incredible speed and built-in native support for `asyncio`. Complex operations (like database interactions and ML anomaly detection) are shoved into background tasks so the main thread never blocks the user.
 Database: `MongoDB` (Motor Async). Logs are, by definition, unstructured. Relational databases like SQLite break down under heavy, chaotic JSON structures. MongoDB is the industry standard backing real SIEMs.
 Frontend: Vanilla JS / HTML / CSS. I bypassed heavy frameworks like React to ensure zero initial load times, utilizing modern Glassmorphism, CSS Grid, and the native `EventSource` API for the live stream.
 Authentication: A custom-built JWT (JSON Web Token) module backed by an automated 6-digit SMTP Email OTP (One-Time Password) system to verify sessions securely.

---

## 🚀 Getting Started Locally

Running the application is incredibly simple. You do not need to configure the database manually.

### Option A: The "One Click" Docker Method (Recommended)
Make sure Docker Desktop is running on your machine.
```bash
# In the root of the project directory
docker-compose up --build -d
```
This command spins up the isolated MongoDB database, builds the Python 3.11 FastAPI container, links them together, and exposes the app on port 8000.

### Option B: The Native Method
If you want to run it directly on your machine for development:

1. Create a virtual environment and install dependencies:
```bash
pip install -r requirements.txt
```
2. Start the Uvicorn server:
```bash
uvicorn main:app --reload
```

Access the Beautiful Dashboard here: 👉 [http://localhost:8000](http://localhost:8000)

---

## 📡 Core API Reference

The entire platform is modular. If you don't want to use the UI, you can hook the engine directly into your own CI/CD pipelines.

POST `/analyze`
Analyzes a payload and returns the risk score, findings, and masked logs.
```json
{
  "input_type": "text", 
  "content": "2024-03-24 ERROR Database timeout password=admin123",
  "options": {
    "mask": true
  }
}
```

GET `/api/stream`
An SSE (Server-Sent Event) connection point to tail the active backend log stream in real-time.
<img width="1919" height="916" alt="Screenshot 2026-03-26 223337" src="https://github.com/user-attachments/assets/82e3987f-e645-44af-8d15-8d9b4573c1fa" />
<img width="1911" height="922" alt="Screenshot 2026-03-26 223420" src="https://github.com/user-attachments/assets/4f37590d-d113-4e17-9c59-6096fc6d40b3" />
<img width="1911" height="914" alt="Screenshot 2026-03-26 223442" src="https://github.com/user-attachments/assets/2b70ceb3-7585-4592-8d4a-e8fc710a177b" />
<img width="1908" height="912" alt="Screenshot 2026-03-26 225751" src="https://github.com/user-attachments/assets/5da2e504-fb52-4e6d-8406-9acbabd7b775" />
<img width="1860" height="916" alt="Screenshot 2026-03-26 225646" src="https://github.com/user-attachments/assets/a865d39a-52e5-42c7-a84b-6c439adc7dee" />
<img width="1915" height="663" alt="Screenshot 2026-03-26 225625" src="https://github.com/user-attachments/assets/8642e829-3c9e-486f-86ee-7dcb60368abb" />
<img width="984" height="568" alt="Screenshot 2026-03-26 223827" src="https://github.com/user-attachments/assets/c8cbece6-ad3e-4bb4-910a-c0b4e62e57ba" />
<img width="1656" height="899" alt="Screenshot 2026-03-26 223459" src="https://github.com/user-attachments/assets/09bf77dd-0b99-4c99-bead-72bd699dc164" />

<img width="1908" height="912" alt="Screenshot 2026-03-26 225751" src="https://github.com/user-attachments/assets/de591068-73d9-4021-b674-b26d48b38b0f" />
![Uploading Screenshot 2026-03-26 223337.png…]()
