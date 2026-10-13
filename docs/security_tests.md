# Security test cases

| ID | Test | Expected | Result | Evidence |
|----|------|----------|--------|----------|
| T03 | Edit a note title directly in the database | HMAC check fails, note flagged | INTEGRITY ERROR shown | T03_before.png, T03_after.png |
| T08 | XSS payloads in note title/content (script tag, img onerror) | Rendered as inert text, no script executed | Escaped as text, no alert | T08_code.png, T08_xss_escaped.png, T08_source.png |
| T09 | 5 wrong passwords then the correct one on the same account | Account locked (423), events logged in audit_log | Lockout observed, account_locked and login_blocked_locked logged | T09_locked.png, T09_db_locked.png, T09_audit_log.png |
| T11 | Serve the app over HTTPS with an OpenSSL certificate and enable the Secure cookie flag | TLS 1.2+ negotiated, cookie flagged Secure | TLS 1.3 negotiated, Secure=true | OPENSSL_cert.png, OPENSSL_tls.png, HTTPS_headers.png, T10_cookie_https.png |
| T11 | Serve the app over HTTPS with an OpenSSL certificate and enable the Secure cookie flag | TLS 1.2+ negotiated, cookie flagged Secure | TLS 1.3 negotiated, Secure=true | OPENSSL_cert.png, OPENSSL_tls.png, HTTPS_headers.png, T10_cookie_https.png |
| T05 | IDOR - Access another user's note by changing the ID | 403 Forbidden or Access Denied | 403 Forbidden | T05_idor.png |
| T14 | Replay a session cookie after logout (Burp Repeater) | Session rejected after logout | Known limitation: the old cookie is still accepted until it expires (30 min). Flask stores the session in a signed client-side cookie, so the server cannot revoke it | T14_session_replay.png |
| T16 | Automated test suite (pytest): authentication, lockout, access control, IDOR, AES-GCM, HMAC, security headers | All tests pass | 21 passed | PYTEST_passed.png |
