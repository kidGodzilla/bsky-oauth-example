# Bluesky OAuth Example

This is a simple example of OAuth 2.0 sign-in for Bluesky, using Node, Express, and Vanilla JS.

Think of it as a starter pack for developing on Atproto with OAuth 2.0.

# Installation

Install npm dependencies (`npm i`) and generate keys for your `.env`.

# Crypto
You can generate your .env file in one go using the included script (macOS).

Generate public/private keypairs (macOS) & create/update .env file:

```bash
sh ./generate_keypairs.sh
```

# Running

Once you've added your keys, you're ready to run `npm i && npm start`

## Cookie-based Auth Option
Additional security benefits can come with using Cookie-based auth, but this is optional. No code changes are required in this example, except your env variable `USE_COOKIES` should be set to 1.
