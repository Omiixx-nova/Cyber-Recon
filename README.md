# CyberRecon Web Suite — Backend Setup Guide

## Quick Start (3 Steps)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Server
```bash
python app.py
```

Server starts at: **http://localhost:5000**

### Step 3: Connect Your Frontend
Your HTML/JS frontend can now call the API using fetch():

```javascript
const response = await fetch("http://localhost:5000/api/dns-lookup", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ domain: "example.com" })
});
const result = await response.json();
console.log(result.data);
```

---

## API Endpoints Reference

| Endpoint              | Method | Input Fields                        |
|-----------------------|--------|-------------------------------------|
| `/api/subdomain-scan` | POST   | `domain`                            |
| `/api/dir-fuzz`       | POST   | `url`, `paths` (array)              |
| `/api/headers`        | POST   | `url`                               |
| `/api/ip-lookup`      | POST   | `ip`                                |
| `/api/whois`          | POST   | `domain`                            |
| `/api/ssl-check`      | POST   | `domain`                            |
| `/api/port-scan`      | POST   | `host`, `ports` (array of numbers)  |
| `/api/dns-lookup`     | POST   | `domain`                            |
| `/api/health`         | GET    | *(none)*                            |

---

## All Response Format

Every endpoint returns:
```json
{
  "status": "success",
  "data": { ... }
}
```

On error:
```json
{
  "status": "error",
  "message": "Description of what went wrong"
}
```

---

## Frontend fetch() Examples

### DNS Lookup
```javascript
fetch("http://localhost:5000/api/dns-lookup", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ domain: "google.com" })
})
.then(r => r.json())
.then(data => console.log(data));
```

### Port Scan
```javascript
fetch("http://localhost:5000/api/port-scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ host: "example.com", ports: [80, 443, 22, 21, 3306] })
})
.then(r => r.json())
.then(data => console.log(data));
```

### SSL Check
```javascript
fetch("http://localhost:5000/api/ssl-check", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ domain: "github.com" })
})
.then(r => r.json())
.then(data => console.log(data));
```

---

## Notes
- CORS is enabled — your frontend on any port can connect freely
- All endpoints have error handling built in
- Port scanner uses multi-threading (fast!)
- Subdomain scanner checks 50+ common subdomains in parallel
- SSL check works on port 443 only (standard HTTPS)
- IP Lookup uses ipinfo.io free tier (no API key needed)
