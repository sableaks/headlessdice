# HEADLESS TP
Needs Node 20+. No npm install.
1. discord.com/developers → New Application → OAuth2: add redirect `BASE_URL/auth/callback`; copy Client ID + Secret.
2. `cp .env.example .env`, fill it in, then `node --env-file=.env server.js`
3. Put it behind HTTPS (BASE_URL must match exactly). Log in with the owner Discord account → /admin.
Keys are stored hashed in data.json (back it up). The owner ID is always admin. Keep .env and data.json private.
