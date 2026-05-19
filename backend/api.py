import codecs
import socket
from urllib.parse import urlparse
import requests
import dns.resolver
import whois
from ipwhois import IPWhois
try:
    import mmh3
except ImportError:
    mmh3 = None
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import concurrent.futures
try:
    from Wappalyzer import Wappalyzer, WebPage
except ImportError:
    Wappalyzer = None


app = FastAPI(title="Recon API", description="One-click Recon API for Chrome Extension")

# Allow CORS for the extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme if parsed.scheme else "http"
    domain = parsed.netloc if parsed.netloc else parsed.path
    return f"{scheme}://{domain}"

def recon_dns(domain: str):
    records = {"A": [], "AAAA": [], "MX": [], "TXT": [], "NS": []}
    for qtype in records.keys():
        try:
            answers = dns.resolver.resolve(domain, qtype)
            records[qtype] = [str(rdata) for rdata in answers]
        except Exception:
            pass
    return records

def recon_asn(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "ip": ip,
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "asn_country_code": res.get("asn_country_code"),
            "network": res.get("network", {}).get("name")
        }
    except Exception as e:
        return {"error": str(e)}

def recon_whois(domain: str):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def resolve_subdomain(subdomain: str):
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip, "status": "live"}
    except Exception:
        return {"subdomain": subdomain, "ip": None, "status": "dead"}

def recon_subdomains(domain: str):
    subdomains = set()
    try:
        # Try crt.sh first
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                if "\n" in name:
                    for n in name.split("\n"):
                        subdomains.add(n.strip())
                else:
                    subdomains.add(name.strip())
    except Exception:
        pass

    # If crt.sh failed or was empty, fallback to HackerTarget
    if not subdomains:
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
            if r.status_code == 200:
                lines = r.text.split("\n")
                for line in lines:
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except Exception as e:
            if not subdomains:
                return {"error": f"Both crt.sh and hackertarget failed."}

    if not subdomains:
        return []
    
    subdomain_list = list(subdomains)[:80] # Limit to 80 for prompt performance
    resolved_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        resolved_results = list(executor.map(resolve_subdomain, subdomain_list))
        
    resolved_results.sort(key=lambda x: x["status"] != "live")
    return resolved_results

def recon_http_info(url: str):
    base_url = get_base_url(url)
    result = {
        "robots_txt": None,
        "sitemap_xml": None,
        "csp": None,
        "favicon_hash": None
    }
    
    # Headers for requests
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0 Safari/537.36"}
    
    try:
        # 1. Main page (CSP + finding favicon)
        res = requests.get(base_url, headers=headers, timeout=10, verify=False)
        result["csp"] = res.headers.get("Content-Security-Policy", "Not Found")
        
        # Try to find favicon in HTML
        soup = BeautifulSoup(res.content, "html.parser")
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        favicon_url = None
        if icon_link and icon_link.get("href"):
            href = icon_link["href"]
            if href.startswith("http"):
                favicon_url = href
            elif href.startswith("//"):
                favicon_url = f"{urlparse(base_url).scheme}:{href}"
            else:
                favicon_url = f"{base_url}/{href.lstrip('/')}"
        else:
            favicon_url = f"{base_url}/favicon.ico"
            
        # 2. Fetch favicon and hash
        try:
            fav_res = requests.get(favicon_url, headers=headers, timeout=5, verify=False)
            if fav_res.status_code == 200:
                favicon = codecs.encode(fav_res.content, "base64")
                if mmh3:
                    favicon_hash = mmh3.hash(favicon)
                    result["favicon_hash"] = favicon_hash
                else:
                    result["favicon_hash"] = "mmh3 module missing"
        except:
            pass
            
        # 3. robots.txt
        try:
            robots_res = requests.get(f"{base_url}/robots.txt", headers=headers, timeout=5, verify=False)
            if robots_res.status_code == 200:
                result["robots_txt"] = robots_res.text[:1000] # truncate if huge
        except:
            pass
            
        # 4. sitemap.xml
        try:
            sitemap_res = requests.get(f"{base_url}/sitemap.xml", headers=headers, timeout=5, verify=False)
            if sitemap_res.status_code == 200 and "xml" in sitemap_res.headers.get("Content-Type", ""):
                result["sitemap_xml"] = "Found"
        except:
            pass
            
    except Exception as e:
        result["error"] = str(e)
        
    return result

def recon_tech_stack(url: str):
    if not Wappalyzer:
        return {"error": "python-Wappalyzer is not installed"}
    try:
        w = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=10)
        techs = w.analyze_with_versions_and_categories(webpage)
        # Simplify the output structure for popup rendering
        formatted_techs = []
        for name, details in techs.items():
            categories = details.get("categories", [])
            versions = details.get("versions", [])
            version_str = versions[0] if versions else None
            formatted_techs.append({
                "name": name,
                "categories": categories,
                "version": version_str
            })
        return formatted_techs
    except Exception as e:
        return {"error": str(e)}

def recon_wayback(domain: str):
    try:
        # Use Internet Archive CDX API
        # Only pull top 100 HTML or API endpoints to keep it extremely fast
        archive_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100&fl=original&collapse=urlkey"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        r = requests.get(archive_url, headers=headers, timeout=10)
        if r.status_code == 200:
            urls_data = r.json()
            if len(urls_data) > 1:
                # Exclude the header row
                urls = [row[0] for row in urls_data[1:]]
                return urls
        return []
    except Exception as e:
        return {"error": str(e)}


def recon_shodan(ip: str):
    if not ip:
        return {"error": "No IP resolved for Shodan lookup"}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"ports": [], "cves": [], "tags": [], "hostnames": [], "detail": "No passive Shodan threat intel found."}
        else:
            return {"error": f"Shodan API returned status code {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/recon")
def do_recon(url: str):
    if not url.startswith("http"):
        url = "http://" + url
    
    domain = get_domain(url)
    
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL")
        
    try:
        target_ip = socket.gethostbyname(domain)
    except Exception:
        target_ip = None
        
    # Use ThreadPoolExecutor to run lookups concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        f_dns = executor.submit(recon_dns, domain)
        f_asn = executor.submit(recon_asn, domain)
        f_whois = executor.submit(recon_whois, domain)
        f_subs = executor.submit(recon_subdomains, domain)
        f_http = executor.submit(recon_http_info, url)
        f_tech = executor.submit(recon_tech_stack, url)
        f_wayback = executor.submit(recon_wayback, domain)
        f_shodan = executor.submit(recon_shodan, target_ip)
        
        result = {
            "target": domain,
            "dns": f_dns.result(),
            "asn": f_asn.result(),
            "whois": f_whois.result(),
            "subdomains": f_subs.result(),
            "http_info": f_http.result(),
            "tech_stack": f_tech.result(),
            "wayback": f_wayback.result(),
            "shodan": f_shodan.result()
        }
        
    return result

if __name__ == "__main__":
    import uvicorn
    # Disable insecure request warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    uvicorn.run(app, host="0.0.0.0", port=8000)
