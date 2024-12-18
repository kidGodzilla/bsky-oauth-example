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

Once you've added your keys, you're ready to run `npm start`

## Cookie-based Auth Option
Additional security benefits can come with using Cookie-based auth, but this is optional. No code changes are required in this example, except your env variable `USE_COOKIES` should be set to 1.

## Testing

You can enable `DEBUG=true` and see logging of the internals of the OAuth process, including what is set at each step in the InMemoryStore.

One interesting thing you can test is token refresh, by logging in, then navigating to the `/revoke` endpoint (cookies required: set `USE_COOKIES=true`).

You will see an `access_token` and `refresh_token` set in the InMemoryStore, and once you revoke the `access_token` it is removed, and expiry is updated to be immediate.

Then, upon refreshing `/`, you will see a request to the API, which initiates the behind-the-scenes token refresh, handled by the Bluesky OAuth library. You receive a new access_token, which is used to seamlessly read the API (without the app knowing this happened). Automagic.

Basically, this demonstrates that all you need to do to build an app with long-lived, unattended API access to Bluesky data is to have the user sign in once, request `refresh_token` in your `client-metadata` configuration, and their token will be refreshed indefinitely.

Some requirement may exist that the token be refreshed every day -- and if this does not occur your app may lose the ability to refresh the token. But as long as you continue to access Bluesky data via Atproto APIs on behalf of the user, you should be able to do so indefinitely, without interaction from the user.

