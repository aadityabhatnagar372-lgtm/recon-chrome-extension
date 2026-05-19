# One-Click Passive Recon - Installation & Usage Guide

Follow these simple instructions to install the dependencies, start the backend server, and load the extension into Google Chrome.

---

## 📋 Prerequisites
Before running, ensure you have:
1. **Python 3.9+** installed. You can verify this by running:
   ```bash
   python --version
   ```

---

## 🛠️ Step 1: Install Python Dependencies
Open your terminal (PowerShell, Command Prompt, or Bash) and navigate to the backend directory:

```bash
cd recon_chrome_extension/backend
```

Install the required Python modules using pip:
```bash
pip install -r requirements.txt
```

---

## 🚀 Step 2: Start the Backend Server
From the backend directory, run:

```bash
python api.py
```

- The API server will start up on **`http://localhost:8000`**.
- Keep this terminal window open while using the extension.

---

## 🔌 Step 3: Install the Chrome Extension
1. Open Google Chrome.
2. Navigate to **`chrome://extensions/`** by typing it in your address bar.
3. In the top-right corner, toggle the **Developer mode** switch to **ON**.
4. In the top-left corner, click the **Load unpacked** button.
5. In the file picker, select the **`recon_chrome_extension/extension`** folder.
6. The extension is now loaded! You will see the One-click Recon icon in your toolbar.

---

## 💻 Step 4: Run the Passive Recon
1. Navigate to any website you want to research (e.g., `https://example.com`).
2. Click the Recon extension icon in your Chrome toolbar.
3. The popup will automatically load the current active tab's domain and kick off the passive recon checks.
4. The results will populate in interactive tabs:
   - **DNS/WHOIS**: Domain registry info, IP locations, subnets, and DNS records.
   - **Subdomains**: Enumerate active subdomains discovered passively.
   - **HTTP/Tech**: Active server headers, Content Security Policies (CSP), sitemaps, robots.txt, and Wappalyzer software profiles.
   - **Passive Intel**: Shodan passive vulnerability records and Wayback historic crawl archives.
