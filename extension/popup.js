document.addEventListener("DOMContentLoaded", async () => {
  const targetEl = document.getElementById("target-url");
  const loadingState = document.getElementById("loading-state");
  const errorState = document.getElementById("error-state");
  const resultsState = document.getElementById("results-state");
  const errorMessage = document.getElementById("error-message");

  // Tab switching logic
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
    });
  });

  try {
    // Get active tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;
    
    if (!url || url.startsWith("chrome://") || url.startsWith("edge://")) {
      throw new Error("Cannot run recon on this page.");
    }
    
    const urlObj = new URL(url);
    targetEl.textContent = urlObj.hostname;

    // Fetch recon data from local backend
    const res = await fetch(`http://localhost:8000/api/recon?url=${encodeURIComponent(url)}`);
    if (!res.ok) {
      throw new Error(`Backend error: ${res.status}`);
    }
    
    const data = await res.json();
    renderReport(data);



    // Export report handler
    const exportBtn = document.getElementById("export-report");
    if (exportBtn) {
      exportBtn.addEventListener("click", () => {
        let md = `# Recon Scope Intelligence Report: ${targetEl.textContent}\n\n`;
        md += `*Generated passively via ReconScope extension on ${new Date().toLocaleString()}*\n\n`;
        
        // Add Overview
        md += `## 1. Network & ASN Information\n`;
        const netEl = document.getElementById("overview-network");
        if (netEl) {
          netEl.querySelectorAll(".kv-item").forEach(item => {
            const key = item.querySelector(".kv-key")?.textContent || "";
            const val = item.querySelector(".kv-val")?.textContent || "";
            md += `* **${key}**: ${val}\n`;
          });
        }
        md += `\n`;
        
        // Add Shodan passive intelligence
        const shodanInfo = document.getElementById("shodan-info");
        const shodanCard = document.getElementById("shodan-card");
        if (shodanCard && shodanCard.style.display !== "none" && shodanInfo) {
          md += `## 1.5 Shodan Threat Intel (Passive)\n`;
          shodanInfo.querySelectorAll(".kv-item").forEach(item => {
            const key = item.querySelector(".kv-key")?.textContent || "";
            const val = item.querySelector(".kv-val")?.textContent || "";
            md += `* **${key}**: ${val}\n`;
          });
          md += `\n`;
        }
        
        // Add DNS
        md += `## 2. DNS Records\n`;
        const dnsEl = document.getElementById("dns-content");
        if (dnsEl) {
          dnsEl.querySelectorAll("h3").forEach(h3 => {
            md += `### ${h3.textContent}\n`;
            const list = h3.nextElementSibling;
            if (list && list.classList.contains("scroll-list")) {
              list.querySelectorAll(".list-item").forEach(item => {
                md += `* \`${item.textContent}\`\n`;
              });
            }
          });
        }
        md += `\n`;
        
        // Add Subdomains
        md += `## 3. Subdomains\n`;
        const subsList = document.getElementById("subdomains-list");
        if (subsList) {
          subsList.querySelectorAll(".list-item").forEach(item => {
            md += `* ${item.textContent.trim()}\n`;
          });
        }
        md += `\n`;
        
        // Add Tech Stack
        md += `## 4. Tech Stack\n`;
        const techList = document.getElementById("tech-list");
        if (techList) {
          techList.querySelectorAll(".list-item").forEach(item => {
            const name = item.querySelector("strong")?.textContent || "";
            const badge = item.querySelector(".badge")?.textContent || "";
            const cat = item.querySelector("div")?.textContent || "";
            md += `* **${name}** ${badge ? `(\`${badge}\`)` : ""} - ${cat}\n`;
          });
        }
        md += `\n`;

        // Add Wayback URLs
        md += `## 5. Wayback Machine Archived URLs\n`;
        const waybackList = document.getElementById("wayback-list");
        if (waybackList) {
          waybackList.querySelectorAll("a").forEach(a => {
            md += `* [${a.textContent}](${a.href})\n`;
          });
        }
        md += `\n`;
        
        // Trigger download
        const blob = new Blob([md], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `recon_report_${targetEl.textContent.replace(/[^a-zA-Z0-9]/g, "_")}.md`;
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    // Show results
    loadingState.classList.add("hidden");
    resultsState.classList.remove("hidden");

  } catch (err) {
    loadingState.classList.add("hidden");
    errorState.classList.remove("hidden");
    errorMessage.textContent = err.message;
  }
});

function renderReport(data) {
  // 1. Overview Tab
  renderOverview(data);
  // 1.5 Shodan Threat Intel Card
  renderShodan(data.shodan);
  // 2. DNS Tab
  renderDNS(data.dns);
  // 3. Subdomains Tab
  renderSubdomains(data.subdomains);
  // 4. Tech Stack Tab
  renderTechStack(data.tech_stack);
  // 5. Wayback Tab
  renderWayback(data.wayback);
  // 6. WHOIS Tab
  renderWhois(data.whois);
}

function renderShodan(shodanData) {
  const card = document.getElementById("shodan-card");
  const el = document.getElementById("shodan-info");
  
  if (!shodanData || shodanData.error || shodanData.detail) {
    card.style.display = "none";
    return;
  }
  
  card.style.display = "block";
  let html = "";
  
  // Ports
  if (shodanData.ports && shodanData.ports.length > 0) {
    const portsStr = shodanData.ports.join(", ");
    html += createKV("Open Ports", `<span style="color:var(--accent); font-weight:bold;">${portsStr}</span>`);
  }
  
  // CVEs count
  if (shodanData.cves && shodanData.cves.length > 0) {
    const cveCount = shodanData.cves.length;
    const cveListStr = shodanData.cves.slice(0, 5).join(", ");
    html += createKV("Vulnerabilities (CVEs)", `<span class="badge missing" style="cursor:pointer;" title="${cveListStr}">${cveCount} Detected</span>`);
  }

  // Tags
  if (shodanData.tags && shodanData.tags.length > 0) {
    html += createKV("Threat Tags", shodanData.tags.join(", "));
  }
  
  if (html === "") {
    card.style.display = "none";
  } else {
    el.innerHTML = html;
  }
}

function createKV(key, val) {
  return `<div class="kv-item">
    <span class="kv-key">${key}</span>
    <span class="kv-val">${val}</span>
  </div>`;
}

function createBadge(type, text) {
  return `<span class="badge ${type}">${text}</span>`;
}

function renderOverview(data) {
  const netEl = document.getElementById("overview-network");
  let netHtml = "";
  
  if (data.asn && !data.asn.error) {
    netHtml += createKV("IP Address", data.asn.ip);
    netHtml += createKV("ASN", data.asn.asn || "N/A");
    netHtml += createKV("Provider", data.asn.asn_description || "N/A");
    netHtml += createKV("Country", data.asn.asn_country_code || "N/A");
  } else {
    netHtml += `<div class="kv-item" style="color:var(--error)">ASN lookup failed</div>`;
  }
  netEl.innerHTML = netHtml;

  const httpEl = document.getElementById("overview-http");
  let httpHtml = "";
  if (data.http_info && !data.http_info.error) {
    const rtxt = data.http_info.robots_txt ? createBadge('found', 'Found') : createBadge('missing', 'Missing');
    httpHtml += createKV("robots.txt", rtxt);
    
    const sxml = data.http_info.sitemap_xml ? createBadge('found', 'Found') : createBadge('missing', 'Missing');
    httpHtml += createKV("sitemap.xml", sxml);
    
    const csp = data.http_info.csp !== "Not Found" ? createBadge('found', 'Present') : createBadge('missing', 'Missing');
    httpHtml += createKV("CSP Header", csp);
    
    if (data.http_info.favicon_hash) {
      document.getElementById("overview-favicon").textContent = data.http_info.favicon_hash;
    }
  } else {
    httpHtml += `<div class="kv-item" style="color:var(--error)">HTTP checks failed</div>`;
  }
  httpEl.innerHTML = httpHtml;
}

function renderDNS(dnsData) {
  const el = document.getElementById("dns-content");
  let html = "";
  
  if (dnsData.error) {
    html = `<div style="color:var(--error)">DNS lookup failed</div>`;
  } else {
    for (const [qtype, records] of Object.entries(dnsData)) {
      if (records && records.length > 0) {
        html += `<h3>${qtype} Records</h3>`;
        html += `<div class="scroll-list" style="max-height: 100px; margin-bottom: 10px;">`;
        records.forEach(r => {
          html += `<div class="list-item">${r}</div>`;
        });
        html += `</div>`;
      }
    }
    if (html === "") {
      html = "<div>No common DNS records found.</div>";
    }
  }
  el.innerHTML = html;
}

function renderSubdomains(subs) {
  const el = document.getElementById("subdomains-list");
  let html = "";
  
  if (subs && subs.error) {
    html = `<div style="color:var(--error)">Subdomain enum failed: ${subs.error}</div>`;
  } else if (subs && subs.length > 0) {
    const liveSubs = subs.filter(s => s.status === "live");
    html += `<div style="color:var(--success); font-family: 'Inter', sans-serif; font-size: 0.8rem; margin-bottom: 8px; font-weight: 600;">Found ${liveSubs.length}/${subs.length} live subdomains</div>`;
    subs.forEach(s => {
      const isLive = s.status === "live";
      const dot = isLive ? `<span style="color:var(--success); margin-right:6px;">🟢</span>` : `<span style="color:var(--text-secondary); opacity:0.5; margin-right:6px;">🔴</span>`;
      const ipStr = s.ip ? `<span style="color:var(--text-secondary); font-size:0.75rem; float:right;">[${s.ip}]</span>` : "";
      
      html += `<div class="list-item" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px; opacity:${isLive ? 1 : 0.65};">
        <span style="display:flex; align-items:center;">${dot}${s.subdomain}</span>
        ${ipStr}
      </div>`;
    });
  } else {
    html = `<div>No subdomains found.</div>`;
  }
  el.innerHTML = html;
}

function renderWhois(whois) {
  const el = document.getElementById("whois-content");
  let html = "";
  
  if (whois.error) {
    html = `<div style="color:var(--error)">WHOIS lookup failed: ${whois.error}</div>`;
  } else {
    html += createKV("Registrar", whois.registrar || "N/A");
    
    // Format dates
    const cdate = Array.isArray(whois.creation_date) ? whois.creation_date[0] : whois.creation_date;
    const edate = Array.isArray(whois.expiration_date) ? whois.expiration_date[0] : whois.expiration_date;
    
    html += createKV("Created", cdate ? new Date(cdate).toLocaleDateString() : "N/A");
    html += createKV("Expires", edate ? new Date(edate).toLocaleDateString() : "N/A");
    
    if (whois.name_servers) {
      const ns = Array.isArray(whois.name_servers) ? whois.name_servers : [whois.name_servers];
      html += `<div style="margin-top: 10px; color: var(--text-secondary); font-size: 0.8rem;">Name Servers:</div>`;
      ns.forEach(n => {
        html += `<div class="list-item" style="margin-top: 5px;">${n}</div>`;
      });
    }
  }
  el.innerHTML = html;
}

function renderTechStack(techs) {
  const el = document.getElementById("tech-list");
  let html = "";
  
  if (techs && techs.error) {
    html = `<div style="color:var(--error)">Tech stack lookup failed: ${techs.error}</div>`;
  } else if (techs && techs.length > 0) {
    techs.forEach(t => {
      const versionStr = t.version ? ` <span class="badge info">${t.version}</span>` : "";
      const cats = t.categories ? t.categories.join(", ") : "";
      html += `<div class="list-item" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
        <div style="font-family: 'Inter', sans-serif;">
          <strong>${t.name}</strong>${versionStr}
          <div style="font-size:0.7rem; color:var(--text-secondary); margin-top:2px;">${cats}</div>
        </div>
      </div>`;
    });
  } else {
    html = "<div>No technologies detected.</div>";
  }
  el.innerHTML = html;
}

function renderWayback(urls) {
  const el = document.getElementById("wayback-list");
  let html = "";
  
  if (urls && urls.error) {
    html = `<div style="color:var(--error)">Wayback enum failed: ${urls.error}</div>`;
  } else if (urls && urls.length > 0) {
    html += `<div style="color:var(--accent); font-family: 'Inter', sans-serif; font-size: 0.8rem; margin-bottom: 8px;">Found ${urls.length} archived URLs</div>`;
    urls.forEach(url => {
      html += `<div class="list-item" style="word-break: break-all; margin-bottom:5px;">
        <a href="${url}" target="_blank" style="color:var(--accent); text-decoration:none; display:block;">${url}</a>
      </div>`;
    });
  } else {
    html = "<div>No archived URLs found.</div>";
  }
  el.innerHTML = html;
}
