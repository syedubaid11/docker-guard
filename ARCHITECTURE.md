# How DockerGuard Works

DockerGuard checks a Docker image (a packaged app) for known security holes, then uses AI to say **which holes to fix first**.

This page explains the parts of the system and how they talk to each other, in plain words.

---

## The parts, as a restaurant

| Part | What it is | Restaurant version |
|---|---|---|
| **Website** (frontend) | The Next.js site you click around in. Lives in a separate repo and is hosted online (e.g. Vercel). | The customer at the table |
| **API** (`src/`) | The Node.js/Express server in this repo. The only part the website talks to. | The waiter: takes orders, brings food back |
| **Worker** (`src/workers/scanWorker.ts`) | Code that does the slow scanning work. Runs **inside the same program as the API**, just in the background. | The cook in the kitchen |
| **Redis** + BullMQ (`src/queues/scanQueue.ts`) | A to-do list of scans waiting to be done. | The order tickets pinned in the kitchen |
| **Trivy server** | A security tool that knows every publicly reported security hole (CVE). | The recipe book of "known bad ingredients" |
| **AI engine** (`ai-engine/`) | A small Python service with a trained model. Guesses how likely each hole is to be actually attacked, and says why. | The head chef who tastes and says "fix this one first" |
| **Database** (PostgreSQL on Neon) | Stores users, scans and the holes found. | The restaurant's notebook |

---

## The big picture

```mermaid
flowchart LR
    U["👤 You<br/>(browser)"] --> FE["Website<br/>(Next.js)"]
    FE -- "HTTPS + login token" --> API

    subgraph Server["One server (docker compose)"]
        API["API + Worker<br/>(Node.js, port 3000)"]
        R[("Redis<br/>job queue")]
        T["Trivy server<br/>(port 4954)"]
        AI["AI engine<br/>(Python, port 8000)"]
        API <-- "add / take jobs" --> R
        API -- "here is the image's package list,<br/>which ones are vulnerable?" --> T
        API -- "how risky is each hole?" --> AI
    end

    API <-- "read / save data" --> DB[("PostgreSQL<br/>(Neon, in the cloud)")]
    API -- "download the image" --> REG["Docker Hub /<br/>image registry"]
    T -- "updates its list of<br/>known holes" --> VDB["Trivy vulnerability<br/>database (internet)"]
```

**Who can talk to whom:**

- The **website only talks to the API**. It never touches Redis, Trivy, the AI engine or the database directly.
- **Redis, Trivy and the AI engine are private.** Only port 3000 (the API) is open to the outside. Inside the server they find each other by name (`redis`, `trivy`, `ai-engine`).
- The **database is outside the server**, hosted by Neon. Only the API connects to it.

---

## Step by step: what happens when you scan an image

```mermaid
sequenceDiagram
    autonumber
    actor You
    participant Web as Website
    participant API as API
    participant DB as Database
    participant Q as Redis queue
    participant W as Worker
    participant T as Trivy
    participant AI as AI engine

    You->>Web: Type "nginx:latest", click Scan
    Web->>API: POST /api/scan { image }
    API->>DB: Save new scan (status PENDING)
    API->>Q: Add job "scan this image"
    API-->>Web: 202 "Got it" + scanId (instant reply)

    loop Every few seconds
        Web->>API: GET /api/scan/:scanId
        API->>DB: Look up scan
        API-->>Web: Status so far
    end

    Q->>W: Hands the job to the worker
    W->>DB: Status → RUNNING
    W->>T: Which packages in this image have known holes?
    T-->>W: List of holes (CVE id, severity, CVSS, ...)
    W->>AI: POST /predict (all holes at once)
    AI-->>W: Risk 0–1 + top 3 reasons for each
    W->>DB: Save holes + risk, status → DONE

    Web->>API: GET /api/scan/:scanId
    API-->>Web: DONE + holes, riskiest first
    Web-->>You: "Fix First" list
```

In words:

1. **You ask for a scan.** The website sends the image name to the API.
2. **The API does not scan right away.** Scanning can take minutes, so the API writes a "scan" row in the database, puts a ticket on the Redis queue, and replies at once with a scan ID.
3. **The website keeps asking "done yet?"** using that scan ID.
4. **The worker picks up the ticket** from Redis and marks the scan as `RUNNING`.
5. **Trivy finds the holes.** The worker runs the Trivy tool, which downloads the image, lists every package inside it, and asks the Trivy server which of those have known holes.
6. **The AI engine ranks them.** The worker sends all holes in one request. For each one the AI returns a risk score (0 = unlikely to be attacked, 1 = very likely) and up to 3 reasons in plain English, like *"Can be attacked over the network"* or *"No login needed"*.
7. **Everything is saved** in one go and the scan becomes `DONE`.
8. **The website shows the results**, sorted so the riskiest holes come first.

---

## What happens when something goes wrong

| Problem | What DockerGuard does |
|---|---|
| Trivy fails or the image doesn't exist | The job is retried up to **3 times** (waiting 5s, 10s, 20s). If it still fails, the scan becomes `FAILED` with the error message. |
| The AI engine is down or slow (over 60s) | The scan **still finishes**. The holes are saved without a risk score and shown at the bottom of the list. |
| A hole has no CVSS v3 data | It is not sent to the AI (the model was never trained on such holes). It is saved without a risk score. |
| Many people scan at once | Jobs wait their turn in Redis. Only `SCAN_CONCURRENCY` scans run at the same time (1 on the small server) so the machine doesn't run out of memory. |

---

## Logging in

```mermaid
sequenceDiagram
    actor You
    participant Web as Website
    participant API as API
    participant DB as Database

    You->>Web: Email + password
    Web->>API: POST /api/login (or /api/signup)
    API->>DB: Find user, check password (bcrypt)
    API-->>Web: Token (valid 7 days)
    Note over Web,API: Every scan request after this carries<br/>"Authorization: Bearer <token>"
    Web->>API: GET /api/scan
    API->>API: Check token is real and not expired
    API-->>Web: Only YOUR scans
```

- Passwords are never stored as plain text, only as a scrambled hash.
- The token is like a wristband at an event: the API checks it on every scan request, and you can only see scans that belong to you.

---

## What is stored

```mermaid
erDiagram
    users ||--o{ Scan : "starts"
    Scan ||--o{ Vulnerability : "finds"

    users {
        int id
        string email
        string password "hashed"
    }
    Scan {
        string image "e.g. nginx:latest"
        enum status "PENDING / RUNNING / DONE / FAILED"
        string errorMessage
    }
    Vulnerability {
        string vulnerabilityId "e.g. CVE-2021-44228"
        string pkgName
        string severity "from Trivy"
        float riskScore "from AI, 0-1"
        string[] riskReasons "from AI"
    }
```

**Severity vs. risk score:** *severity* (from Trivy) says how bad a hole *could* be. *Risk score* (from the AI) says how likely it is that attackers will *actually* use it. The list is sorted by risk score.

---

## API endpoints (what the website can call)

| Method | Path | Login needed | What it does |
|---|---|---|---|
| POST | `/api/signup` | No | Create an account, get a token |
| POST | `/api/login` | No | Log in, get a token |
| POST | `/api/scan` | Yes | Start a scan, get a `scanId` |
| GET | `/api/scan` | Yes | Your last 50 scans |
| GET | `/api/scan/:scanId` | Yes | One scan with its holes, riskiest first |
| GET | `/health` | No | Is the API up and can it reach the database? |

---

## Running it

Everything except the database starts with one command (see [docker-compose.yml](docker-compose.yml)):

```
docker compose up -d --build
```

This starts 4 containers: `api`, `redis`, `trivy`, `ai-engine`. The database connection and secrets come from `.env` (see [.env.sample](.env.sample)).
