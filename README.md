# One-Click Passive Recon Chrome Extension & Backend

A lightweight, automated passive reconnaissance engine designed for security researchers, penetration testers, and bug bounty hunters. 

With a single click, this Chrome Extension extracts the current webpage host and aggregates high-fidelity passive intelligence from dns records, registrars, active subdomains, technologies, historic web archives, and Shodan passives in under 10 seconds.

---

## 🏗️ Architecture & Features

The tool uses a **FastAPI backend** running high-concurrency lookups via `ThreadPoolExecutor` and beautiful **vanilla Javascript/CSS extension frontend** to query the following passive reconnaissance fields:

1. **DNS Reconnaissance:** Live querying for `A`, `AAAA`, `MX`, `TXT`, and `NS` records using `dnspython`.
2. **ASN & Network Intel:** Reverse IP lookups mapping network owner, ASN, description, and registered country code via RDAP.
3. **WHOIS Data:** Queries domain creation date, expiration date, name servers, and registrar information.
4. **Subdomain Enumeration:** Fetches subdomains concurrently from Certificate Transparency logs (`crt.sh`) and falls back to HackerTarget API, resolving IP status concurrently.
5. **HTTP Footprinting:** Scrapes security headers, parses `Content-Security-Policy` (CSP), extracts favicon URLs, computes MMH3 favicon hashes, and inspects `robots.txt` / `sitemap.xml`.
6. **Technology Profiling:** Analyzes server stacks, client libraries, CMSs, and applications using Wappalyzer.
7. **Wayback Archives:** Crawls Wayback machine CDX indexes to find popular endpoints or hidden paths.
8. **Shodan passive threat intel:** Performs passive host analysis via Shodan InternetDB (finding open ports, vulnerabilities, CVEs, and passive tags) without making direct contact with the target.

---

## 🛠️ Installation & Setup

### 1. Backend Setup

#### Prerequisites
- **Python 3.9+**
- Visual C++ Build Tools (optional, required if installing `mmh3` on Windows from source, though pre-compiled wheels are available via `pip`).

#### Running the Backend
1. Open your terminal and navigate to the backend directory:
   ```bash
   cd recon_chrome_extension/backend
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI server using Uvicorn:
   ```bash
   python api.py
   ```
   *The backend will boot up on `http://localhost:8000`.*

---

### 2. Chrome Extension Installation

1. Open Google Chrome (or any Chromium-based browser like Brave, Edge, Opera).
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** in the top-left corner.
5. Select the `recon_chrome_extension/extension` directory from your file system.
6. The extension is now successfully installed. 

---

## 🚀 How to Run the Recon

1. Browse to any website you want to run passive recon on (e.g., `https://example.com`).
2. Click the **One-click Recon** extension icon in your browser toolbar.
3. The popup will automatically load the current active tab's domain and click **Run Recon** for you.
4. The backend will fetch and return structured, categorized passive data in seconds.
5. Tap between the tab panels (**DNS/WHOIS**, **Subdomains**, **HTTP/Tech**, **Passive Intel/Wayback**) to view the results.

---

## 🐳 Backend API Endpoints

- **`GET /api/recon?url={url}`**: Primary orchestrator endpoint that runs the concurrent sub-recon execution loops and returns aggregated intelligence as JSON.
