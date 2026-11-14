# Hosted deployment — Batman Bug Hunter

## Current architecture

- Cloudflare Pages serves the public website and the command-center UI.
- A Cloudflare Pages Function at `/api/*` proxies API calls to the Render service.
- Render runs `batman_hunter.hosted_api:APP`.
- Accounts, DNS-verification challenges, verified domains, and reports are stored in SQLite on a Render persistent disk.
- The hosted scanner permits only HTTPS on port 443, passive checks, and domains verified by a per-user DNS TXT challenge.
- Nmap, private-network recon, loopback training probes, and local Windows event collection remain local-only.

## Deploy backend to Render

1. Push/merge the hosted backend branch to `main` after reviewing and testing it.
2. In Render, choose **New → Blueprint** and connect this GitHub repository.
3. Render should detect the root `render.yaml`. Review the service and persistent-disk pricing before confirming. The blueprint uses a paid Starter service and a 1 GB persistent disk because a free ephemeral filesystem is not suitable for account/report persistence.
4. Set `FRONTEND_ORIGIN` to `https://batman-bug-hunter.pages.dev` if the Pages hostname changes.
5. Deploy. Confirm `https://YOUR-RENDER-SERVICE.onrender.com/api/health` returns JSON with `"status":"ok"`.
6. In Cloudflare Pages → Settings → Environment variables, add:
   - `BACKEND_URL` = `https://YOUR-RENDER-SERVICE.onrender.com`
   Apply to Production and Preview only if the matching frontend origin is allowed by the API CORS policy.
7. Trigger a new Pages deployment so the Function receives the environment variable.
8. Open `https://batman-bug-hunter.pages.dev/app.html`, create an account, sign in, add the DNS TXT record shown by the app, verify it, and run a passive scan against that verified HTTPS domain.

## Important operational notes

- Do not put Render credentials, database passwords, or API tokens in GitHub files or chat.
- The Render blueprint's persistent disk is a paid resource. Do not confirm the service until you have reviewed the current price in Render.
- Rate limiting currently uses the Flask-Limiter in-memory backend and one Gunicorn worker. This is a first hosted beta, not a horizontally scaled deployment. Add managed Redis before increasing worker count or scaling instances.
- Account email verification, password reset, MFA, billing, team accounts, and abuse-monitoring workflows are not included yet. Do not treat this as a mature commercial SaaS.
- Passwords are hashed; API bearer tokens are stored as SHA-256 hashes. Tokens expire after seven days and are held in browser session storage.
- Do not submit sensitive customer evidence. The hosted version currently stores scan reports only; file-analysis workflows remain local.
- A DNS TXT proof demonstrates control of the domain at verification time. It does not grant permission to test every path or service; follow written scope and applicable program rules.
- Never scan a third-party target without explicit authorization.
