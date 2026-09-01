# NTLMv2 Phishing PoC

Cloudflare Worker that turns UNC-based Net-NTLMv2 leakage into a practical phishing flow. UNC path never appears in HTML source, only returned after Turnstile verification.

---

## Quick Start

### 1. Deploy Worker

1. Cloudflare Dashboard → Workers & Pages → Create application → Create Worker
2. Name it (e.g. `ntlm-phishing`)
3. Click Deploy
4. Click Edit code, replace with worker.js
5. Save and Deploy

### 2. Get Turnstile Keys

1. Cloudflare Dashboard → Turnstile → Add a site
2. Site name: any (e.g., `phishing-poc`)
3. Domain: your worker domain (e.g. `your-domain.com`)
4. Create → Copy Site Key and Secret Key

### 3. Set Environment Variables

Worker → Settings → Variables:

**Secrets:**

| Variable | Value |
|----------|-------|
| `TURNSTILE_SITE_KEY` | your site key |
| `TURNSTILE_SECRET_KEY` | your secret key |
| `TEAMS_WEBHOOK_URL` | your Teams webhook (optional) |

**Variables:**

| Variable | Value |
|----------|-------|
| `TARGET_PATH` | `\\YOUR_SERVER_IP\sharename` |
| `ALLOWED_DOMAIN` | `your-domain.com` |
| `REDIRECT_URL` | `https://smbdsecurity.com` |

### 4. Set Up Responder

On your EC2/VPS:

```bash
responder -I eth0
```
TCP/445 must be reachable from target.
