from flask import Flask, jsonify, request, render_template_string
import socket
import ssl
import datetime
import concurrent.futures
import urllib.request
import urllib.error
import json
import os

app = Flask(__name__)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

def dns_lookup(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = None
        return {"status": "ok", "ip": ip, "hostname": hostname}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def port_scan(ip):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)

def check_ssl(target):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            expire = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire - datetime.datetime.utcnow()).days
            return {
                "status": "ok",
                "valid": True,
                "expires": cert['notAfter'],
                "days_left": days_left,
                "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                "subject": dict(x[0] for x in cert['subject']).get('commonName', target),
                "warning": days_left < 30
            }
    except ssl.SSLCertVerificationError as e:
        return {"status": "ok", "valid": False, "error": str(e)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_headers(target):
    security_headers = {
        "Strict-Transport-Security": {"risk": "HIGH", "desc": "Forces HTTPS connections"},
        "X-Frame-Options": {"risk": "MEDIUM", "desc": "Prevents clickjacking"},
        "X-Content-Type-Options": {"risk": "MEDIUM", "desc": "Prevents MIME sniffing"},
        "Content-Security-Policy": {"risk": "HIGH", "desc": "Prevents XSS attacks"},
        "Referrer-Policy": {"risk": "LOW", "desc": "Controls referrer info"},
        "Permissions-Policy": {"risk": "LOW", "desc": "Controls browser features"},
        "X-XSS-Protection": {"risk": "LOW", "desc": "Legacy XSS filter"},
    }
    present = {}
    missing = {}
    server_info = None
    powered_by = None
    try:
        for scheme in ["https", "http"]:
            try:
                req = urllib.request.Request(
                    f"{scheme}://{target}",
                    headers={"User-Agent": "SecurityScanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    headers = dict(resp.headers)
                    server_info = headers.get("Server") or headers.get("server")
                    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
                    for h, meta in security_headers.items():
                        if h.lower() in {k.lower() for k in headers}:
                            present[h] = {"desc": meta["desc"], "risk": meta["risk"]}
                        else:
                            missing[h] = {"desc": meta["desc"], "risk": meta["risk"]}
                    break
            except urllib.error.URLError:
                continue
    except Exception as e:
        pass
    return {
        "present": present,
        "missing": missing,
        "server": server_info,
        "powered_by": powered_by
    }

def calc_risk_score(dns, ports, ssl_info, headers):
    score = 100
    findings = []

    if dns.get("status") == "error":
        return 0, ["Target unreachable"]

    risky_ports = {21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
                   6379: "Redis", 27017: "MongoDB", 3389: "RDP", 445: "SMB"}
    for p in ports:
        if p in risky_ports:
            score -= 15
            findings.append(f"Exposed {risky_ports[p]} port {p}")

    if ssl_info.get("status") == "error" or not ssl_info.get("valid", True):
        score -= 20
        findings.append("SSL certificate invalid or missing")
    elif ssl_info.get("warning"):
        score -= 10
        findings.append(f"SSL expires in {ssl_info.get('days_left')} days")

    high_missing = [h for h, m in headers.get("missing", {}).items() if m["risk"] == "HIGH"]
    med_missing = [h for h, m in headers.get("missing", {}).items() if m["risk"] == "MEDIUM"]
    score -= len(high_missing) * 10
    score -= len(med_missing) * 5
    for h in high_missing:
        findings.append(f"Missing security header: {h}")
    for h in med_missing:
        findings.append(f"Missing header: {h}")

    if headers.get("server"):
        score -= 5
        findings.append(f"Server version exposed: {headers['server']}")
    if headers.get("powered_by"):
        score -= 5
        findings.append(f"Technology exposed: {headers['powered_by']}")

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade, findings

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan — Security Scanner</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
.navbar{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:12px}
.navbar .logo{font-size:18px;font-weight:600;color:#58a6ff;letter-spacing:-0.5px}
.navbar .tagline{font-size:13px;color:#8b949e}
.container{max-width:900px;margin:0 auto;padding:40px 24px}
.hero{text-align:center;margin-bottom:40px}
.hero h1{font-size:32px;font-weight:700;color:#e6edf3;margin-bottom:8px}
.hero p{font-size:15px;color:#8b949e}
.scan-box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px;margin-bottom:32px}
.scan-input{display:flex;gap:10px}
.scan-input input{flex:1;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px 16px;color:#e6edf3;font-size:15px;outline:none;transition:border-color .2s}
.scan-input input:focus{border-color:#58a6ff}
.scan-input input::placeholder{color:#484f58}
.scan-btn{background:#238636;border:none;border-radius:8px;padding:12px 24px;color:#fff;font-size:15px;font-weight:500;cursor:pointer;white-space:nowrap;transition:background .2s}
.scan-btn:hover{background:#2ea043}
.scan-btn:disabled{background:#21262d;color:#484f58;cursor:not-allowed}
.examples{margin-top:12px;font-size:13px;color:#8b949e}
.examples span{color:#58a6ff;cursor:pointer;margin-right:12px}
.examples span:hover{text-decoration:underline}
#results{display:none}
.score-card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px;margin-bottom:20px;display:flex;align-items:center;gap:24px}
.score-circle{width:90px;height:90px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;font-weight:700}
.score-circle .grade{font-size:32px}
.score-circle .num{font-size:13px;opacity:.8}
.grade-A{background:#0d4429;border:2px solid #238636;color:#3fb950}
.grade-B{background:#1c2a0e;border:2px solid #4d7c0f;color:#84cc16}
.grade-C{background:#2d1f00;border:2px solid #b45309;color:#f59e0b}
.grade-D{background:#2d1200;border:2px solid #b45309;color:#fb923c}
.grade-F{background:#2d0000;border:2px solid #da3633;color:#f85149}
.score-info h2{font-size:20px;font-weight:600;margin-bottom:4px}
.score-info p{font-size:14px;color:#8b949e}
.findings{margin-top:12px}
.finding{display:flex;align-items:center;gap:8px;font-size:13px;color:#f85149;margin-top:6px}
.finding::before{content:"⚠";font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px}
.card h3{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.info-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #21262d;font-size:13px}
.info-row:last-child{border-bottom:none}
.info-label{color:#8b949e}
.info-val{color:#e6edf3;font-family:monospace;font-size:12px}
.port-list{display:flex;flex-wrap:wrap;gap:6px}
.port-tag{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:3px 10px;font-size:12px;font-family:monospace}
.port-tag.risky{background:#2d0000;border-color:#da3633;color:#f85149}
.header-row{display:flex;align-items:center;gap-8px;padding:5px 0;font-size:13px;border-bottom:1px solid #21262d}
.header-row:last-child{border-bottom:none}
.hbadge{font-size:10px;padding:2px 6px;border-radius:4px;margin-left:auto;font-weight:500}
.hbadge-present{background:#0d4429;color:#3fb950}
.hbadge-HIGH{background:#2d0000;color:#f85149}
.hbadge-MEDIUM{background:#2d1200;color:#fb923c}
.hbadge-LOW{background:#1c1c00;color:#d4a017}
.ssl-ok{color:#3fb950}
.ssl-warn{color:#f59e0b}
.ssl-bad{color:#f85149}
.loader{text-align:center;padding:40px;color:#8b949e}
.spinner{display:inline-block;width:32px;height:32px;border:3px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .8s linear infinite;margin-bottom:12px}
@keyframes spin{to{transform:rotate(360deg)}}
.status-steps{display:flex;flex-direction:column;gap:6px;margin-top:12px}
.step{font-size:13px;color:#8b949e;display:flex;align-items:center;gap:8px}
.step.done{color:#3fb950}
.step.active{color:#58a6ff}
.full-width{grid-column:1/-1}
@media(max-width:600px){.grid{grid-template-columns:1fr}.scan-input{flex-direction:column}}
</style>
</head>
<body>
<nav class="navbar">
  <div class="logo">⚡ VulnScan</div>
  <div class="tagline">Security Vulnerability Scanner</div>
</nav>
<div class="container">
  <div class="hero">
    <h1>Scan Any Target</h1>
    <p>Instant security report — ports, SSL, headers, risk score</p>
  </div>
  <div class="scan-box">
    <div class="scan-input">
      <input type="text" id="targetInput" placeholder="Enter domain or IP (e.g. example.com)" onkeydown="if(event.key==='Enter')startScan()"/>
      <button class="scan-btn" id="scanBtn" onclick="startScan()">Scan Target</button>
    </div>
    <div class="examples">
      Try: <span onclick="setTarget('example.com')">example.com</span>
      <span onclick="setTarget('github.com')">github.com</span>
      <span onclick="setTarget('google.com')">google.com</span>
    </div>
  </div>
  <div id="loader" style="display:none" class="loader">
    <div class="spinner"></div>
    <div id="loaderText">Scanning target...</div>
    <div class="status-steps" id="statusSteps"></div>
  </div>
  <div id="results"></div>
</div>
<script>
function setTarget(t){document.getElementById('targetInput').value=t}
async function startScan(){
  const target=document.getElementById('targetInput').value.trim();
  if(!target)return;
  document.getElementById('scanBtn').disabled=true;
  document.getElementById('results').style.display='none';
  document.getElementById('loader').style.display='block';
  const steps=[
    'Resolving DNS...',
    'Scanning ports...',
    'Checking SSL certificate...',
    'Auditing security headers...',
    'Calculating risk score...'
  ];
  let si=0;
  const stepsEl=document.getElementById('statusSteps');
  stepsEl.innerHTML=steps.map((s,i)=>`<div class="step" id="step${i}">◦ ${s}</div>`).join('');
  const interval=setInterval(()=>{
    if(si>0)document.getElementById('step'+(si-1)).className='step done';
    if(si<steps.length){document.getElementById('step'+si).className='step active';si++;}
  },800);
  try{
    const res=await fetch('/api/scan',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target})
    });
    const data=await res.json();
    clearInterval(interval);
    steps.forEach((_,i)=>{document.getElementById('step'+i).className='step done';});
    setTimeout(()=>{
      document.getElementById('loader').style.display='none';
      renderResults(data);
    },500);
  }catch(e){
    clearInterval(interval);
    document.getElementById('loader').style.display='none';
    document.getElementById('results').innerHTML='<div style="color:#f85149;padding:20px">Scan failed: '+e.message+'</div>';
    document.getElementById('results').style.display='block';
  }
  document.getElementById('scanBtn').disabled=false;
}
function renderResults(d){
  const r=document.getElementById('results');
  r.style.display='block';
  if(d.error){r.innerHTML='<div style="color:#f85149;padding:20px">Error: '+d.error+'</div>';return;}
  const risky={21:1,23:1,3306:1,5432:1,6379:1,27017:1,3389:1,445:1};
  const portTags=(d.ports||[]).map(p=>`<span class="port-tag ${risky[p]?'risky':''}">${p}</span>`).join('')||'<span style="color:#3fb950;font-size:13px">No open risky ports</span>';
  const sslBadge=d.ssl.valid===false?'<span class="ssl-bad">Invalid</span>':
    d.ssl.warning?`<span class="ssl-warn">${d.ssl.days_left} days left</span>`:
    d.ssl.status==='error'?'<span class="ssl-bad">Error</span>':
    `<span class="ssl-ok">${d.ssl.days_left} days left</span>`;
  const allHeaders={...d.headers.present,...d.headers.missing};
  const headerRows=Object.entries(allHeaders).map(([h,m])=>{
    const present=d.headers.present[h];
    return `<div class="header-row"><span style="color:${present?'#e6edf3':'#8b949e'}">${h}</span><span class="hbadge ${present?'hbadge-present':'hbadge-'+m.risk}">${present?'Present':m.risk}</span></div>`;
  }).join('');
  const findingsList=(d.findings||[]).map(f=>`<div class="finding">${f}</div>`).join('');
  r.innerHTML=`
    <div class="score-card">
      <div class="score-circle grade-${d.grade}"><div class="grade">${d.grade}</div><div class="num">${d.score}/100</div></div>
      <div class="score-info">
        <h2>${d.target}</h2>
        <p>IP: ${d.dns.ip||'Unknown'} ${d.dns.hostname?'· '+d.dns.hostname:''}</p>
        <div class="findings">${findingsList||'<div style="color:#3fb950;font-size:13px">No critical issues found</div>'}</div>
      </div>
    </div>
    <div class="grid">
      <div class="card">
        <h3>🔌 Open Ports</h3>
        <div class="port-list">${portTags}</div>
      </div>
      <div class="card">
        <h3>🔒 SSL Certificate</h3>
        ${d.ssl.status==='error'?`<div class="info-row"><span class="info-label">Status</span><span class="ssl-bad">Not available</span></div>`:`
        <div class="info-row"><span class="info-label">Valid</span>${sslBadge}</div>
        <div class="info-row"><span class="info-label">Issuer</span><span class="info-val">${d.ssl.issuer||'—'}</span></div>
        <div class="info-row"><span class="info-label">Expires</span><span class="info-val">${d.ssl.expires||'—'}</span></div>
        `}
      </div>
      <div class="card full-width">
        <h3>🛡 Security Headers</h3>
        ${headerRows}
        ${d.headers.server?`<div class="info-row" style="margin-top:8px"><span class="info-label">Server</span><span class="info-val" style="color:#fb923c">${d.headers.server}</span></div>`:''}
      </div>
    </div>`;
}
</script>
</body>
</html>'''

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    if not target:
        return jsonify({"error": "No target provided"}), 400
    dns = dns_lookup(target)
    if dns["status"] == "error":
        return jsonify({"error": f"Cannot resolve {target}", "target": target})
    ip = dns["ip"]
    ports = port_scan(ip)
    ssl_info = check_ssl(target)
    headers = check_headers(target)
    score, grade, findings = calc_risk_score(dns, ports, ssl_info, headers)
    return jsonify({
        "target": target,
        "dns": dns,
        "ports": ports,
        "ssl": ssl_info,
        "headers": headers,
        "score": score,
        "grade": grade,
        "findings": findings
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
