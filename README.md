# bsky-oauth-example

This is a simple bare-bones example of oAuth 2.0 for Bluesky, using Node, Express, and Vanilla JS.

Think of it as a starter pack for developing on Atproto with OAuth 2.0.

# Installation

Install npm dependencies (`npm i`) and generate keys for your `.env`.

# Crypto
Examples for macOS:

Generating a signing secret for JWT: `openssl rand -base64 32`

Or, you can generate your .env file in one go using the included script.

Generate public/private keypairs (macOS) & update .env file:

```bash
sh ./generate_keypairs.sh
```

# Running

Once you've added your keys, you're ready to run `npm i && npm start`;

## Cookie-based Auth Option
Additional security benefits come with using Cookie-based auth, but this is optional. No code changes are required in this example, except your env variable `USE_COOKIES` should be set to 1.
