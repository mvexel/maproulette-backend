# OAuth provider for native and desktop apps

MapRoulette's web login sets a session cookie, and scripts use a personal API
key. Neither fits a phone app or a desktop editor plugin: the app would have to
embed a browser session or ask the user to paste their API key. This backend
can also act as an **OAuth 2.0 authorization server** for approved public
clients, such as mobile apps and the JOSM MapRoulette plugin. The user signs in
with OpenStreetMap in the system browser, approves the app on a consent page,
and the app gets short-lived, scoped tokens that act as that MapRoulette user.

It is **off by default** (`oauthProvider.enabled = false`). Off, the new routes
answer 404 and every request is handled as before. On, requests without
`Authorization: Bearer ...` are still handled as before; existing web sessions
and API keys are unchanged.

## How it works

1. The app opens `GET /oauth/authorize` in the system browser with its client id,
   exact redirect URI, scope, `state` and an S256 PKCE challenge.
2. The backend stores the interaction (hashed), binds it to an HTTP-only cookie
   and redirects to OSM's `/oauth2/authorize` with the backend's own OSM
   application (`osm.consumerKey`/`consumerSecret`), asking only for
   `read_prefs`.
3. OSM redirects to `GET /oauth/callback`. The backend exchanges the OSM code
   server-side, reads the user's OSM id, finds or creates the MapRoulette user
   by `users.osm_id`, and shows a consent page naming the app and what it may
   do. The OSM token is not stored.
4. On **Allow**, `POST /oauth/consent` redirects to the app's callback with a
   short-lived code and the app's `state`.
5. The app exchanges the code and its PKCE verifier at `POST /oauth/token` for
   an access token (15 minutes by default) and a refresh token (30 days,
   rotated on every use).
6. The app calls the API with `Authorization: Bearer <access token>`.
   `OAuthBearerFilter` checks the method and exact route against the
   allowlist for the grant's scopes, and only then attaches the user to the
   request, so `SessionManager` treats it as that user.

The protocol work (code and refresh grants, PKCE) uses
[`scala-oauth2-core`](https://github.com/nulab/scala-oauth2-provider). The
code lives in `app/org/maproulette/auth/oauth/` and
`app/controllers/OAuthProviderController.scala`.

## Configuration

Register the backend callback (`https://<backend>/oauth/callback`) as a redirect
URI of the OSM OAuth application in `osm.consumerKey`, then:

```hocon
oauthProvider {
  enabled = true
  callbackUri = "https://maproulette.example.org/oauth/callback"
  clients = [
    {
      id = "example-app"
      name = "Example App"
      redirectUris = ["org.example.app:/oauth/callback"]
      scopes = ["tasks:read", "tasks:write"]
    },
    {
      id = "josm"
      name = "JOSM MapRoulette plugin"
      redirectUris = ["http://127.0.0.1:8111/oauth_authorization"]
      scopes = ["tasks:read", "tasks:write", "tasks:edit"]
    }
  ]
}
```

- Clients are public: no client secret, and no dynamic registration. A client
  may request only scopes its configuration lists (`scopes` defaults to
  `["tasks:read"]`). `enabled = false` on a client refuses its sign-ins,
  refreshes and tokens; revocation still works.
- Redirect URIs match exactly. Accepted forms: `https` with a host, a
  reverse-domain custom scheme (`org.example.app:/...`), or, for desktop apps,
  `http` on a loopback IP literal with an explicit port and path
  (`http://127.0.0.1:8111/...` or `http://[::1]:<port>/...`, RFC 8252 §7.3).
  `localhost`, query strings, fragments and user info are refused.
- `accessSeconds` (default 900, at most 3600) and `refreshSeconds` (default
  2592000, at most 90 days) set token lifetimes. A browser interaction lasts 10
  minutes and a code 2 minutes.
- `allowInsecureLoopback = true` allows an `http://127.0.0.1` callback URI for
  local development only.
- Storage calls run on `oauth-provider-dispatcher`, defined next to the
  `oauthProvider` block in `application.conf`.

Evolution 130 adds the tables `oauth_interactions`, `oauth_families` (one per
approved grant), `oauth_codes`, `oauth_access_tokens` and
`oauth_refresh_tokens`. Codes and tokens are stored only as SHA-256 hashes.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /oauth/authorize` | Start sign-in: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`. |
| `GET /oauth/callback` | OSM's redirect back to the backend. Must match the stored interaction and its cookie. |
| `POST /oauth/consent` | The consent form (CSRF-bound). Allow redirects to the app with `code` and `state`; Cancel with `error=access_denied`. |
| `POST /oauth/token` | Form-encoded `grant_type=authorization_code` (`client_id`, `redirect_uri`, `code`, `code_verifier`) or `grant_type=refresh_token` (`client_id`, `refresh_token`, optional `scope` equal to the grant's). Returns `access_token`, `token_type=Bearer`, `expires_in`, `refresh_token`, `scope`. |
| `POST /oauth/revoke` | Form-encoded `client_id` and `token`: revokes that token's grant. Unknown tokens also answer 200. |
| `GET /oauth/me` | Bearer identity: `id`, `osmId`, `displayName`, `scope`. Never an API key or OSM credential. |

Errors use the RFC 6749 codes (`invalid_request`, `invalid_client`,
`invalid_grant`, `invalid_scope`, `unsupported_grant_type`). Password,
client-credentials and implicit grants are not supported.

## Scopes

A grant always includes `tasks:read`. Scope strings are single-space separated,
unique and stored in the order `tasks:read tasks:write tasks:edit`.

**`tasks:read`**: `GET` of `/api/v2/challenges/extendedFind`,
`/api/v2/challenge/:id`, `/api/v2/challenge/:id/tags`,
`/api/v2/challenge/:id/tasks`, `/api/v2/task/:id`, `/api/v2/tasks/box/...` and
`/oauth/me`, plus the read-only `PUT /api/v2/markers/box/...`. Not every legacy
`GET` is read-only (some lock, or return API keys), so reads are an explicit
list.

**`tasks:write`** adds the task lifecycle, with no query string and no body:

| Route | Purpose |
| --- | --- |
| `GET /api/v2/task/:id/start` | Lock the task |
| `GET /api/v2/task/:id/release` | Release the caller's lock |
| `POST /api/v2/task/:id/skip` | Skip |
| `PUT /api/v2/task/:id/(1\|2\|5\|6)` | Fixed, Not an issue, Already fixed, Too hard |

So a `tasks:write` app can't send `requestReview`, tags or completion
responses, and can't refresh a lock: it locks just before writing the status.

**`tasks:edit`** (requires `tasks:write`) is for desktop editors, which hold a
task for a whole editing session and record more than a status:

| Route | Query keys | Body |
| --- | --- | --- |
| `PUT /api/v2/task/:id/(1\|2\|5\|6)` | `requestReview` (`true` only), `tags` | optional JSON completion responses |
| `POST /api/v2/task/:id/comment` | `actionId` | required JSON |
| `GET /api/v2/task/:id/refreshLock` | none | none |
| `PUT /api/v2/task/:id/changeset` | `changesetId` | none |
| `POST /api/v2/taskBundle` | none | required JSON |
| `POST /api/v2/taskBundle/:id`, `DELETE /api/v2/taskBundle/:id` | none | none |
| `POST /api/v2/taskBundle/:id/update`, `.../unbundle`, `POST /api/v2/task/bundle/unlock` | `taskIds` (required) | none |
| `PUT /api/v2/task/:id/lockBundle` | `taskIds` | none |
| `PUT /api/v2/taskBundle/:id/(1\|2\|5\|6)` | `primaryId` (required), `requestReview` (`true` only), `tags` | optional JSON |
| `POST /api/v2/taskBundle/:id/comment` | `actionId` | required JSON |

Each key appears once, except `taskIds` (at most 50 values); values are at most
1024 characters; bodies are `application/json`, 1 to 16384 bytes, not chunked.
`requestReview=false` is refused because it would skip a review the user's
settings require. Review, meta-review, deletes of tasks and every other route
stay closed.

Every other route answers `403 insufficient_scope` to a bearer token. A request
outside an allowed shape is `400 invalid_request` before the token is checked.
An unknown, expired or revoked token, or one whose client no longer allows its
scopes, is `401 invalid_token`. The user's own MapRoulette permissions still
apply on every allowed route.

## Credentials

- Send the access token only as `Authorization: Bearer ...`. A bearer request
  that also carries an `apiKey` header or a web session is refused (`401`); a
  bearer token never falls back to another credential.
- Codes are single use, consumed in the same transaction that issues the
  tokens. Refresh tokens rotate; presenting a used one revokes the whole grant,
  including its current access token. Apps should serialize refreshes and
  replace stored tokens atomically.
- A refresh can restate the grant's scope but never widen or narrow it. To
  gain `tasks:write`, the user signs in again and approves it, which creates a
  new grant. Removing a scope from a client's configuration makes its existing
  grants with that scope stop authenticating.
- Revocation affects one grant, not the user's other apps, web session or API
  key. OAuth sign-in never changes an existing user's API key or web-session
  token.

## Accounts

The callback looks up the user by numeric OSM id, so on the same MapRoulette
instance web login and OAuth sign-in reach the same account and permissions. A
first OAuth sign-in creates the user and their home project, as web login does.

## Tests

The service, controller, scope and filter specs use mocks and need no database.
`OAuthRepositorySpec` and `OAuthUserProvisionerSpec` run real PostgreSQL
transactions (concurrent code redemption, refresh rotation, replay revocation)
in a fresh schema per case on a disposable database: set
`OAUTH_TEST_DATABASE_URL`, and optionally `OAUTH_TEST_DATABASE_USER` and
`OAUTH_TEST_DATABASE_PASSWORD`; without them they are canceled. CI creates
`oauth_ci` for them.

```sh
sbt 'testOnly org.maproulette.auth.oauth.*'
```

`scripts/oauth-test-osm.mjs` is a loopback-only synthetic OSM provider, and
`scripts/oauth-smoke.mjs` runs the whole browser flow against a local backend
(state and cookie binding, consent, PKCE, identity, a refused route, refresh
rotation, replay revocation and revocation). Run the backend on
`127.0.0.1:9000` with a disposable database, `osm.server` at
`http://127.0.0.1:9001`, `osm.consumerKey = "oauth-test-upstream"`, the same
secret in `osm.consumerSecret` and `OAUTH_TEST_OSM_SECRET`, and:

```hocon
oauthProvider {
  enabled = true
  allowInsecureLoopback = true
  callbackUri = "http://127.0.0.1:9000/oauth/callback"
  clients = [{id = "example-app", name = "Example App", redirectUris = ["org.maproulette.example:/oauth2redirect"]}]
}
```

then `node scripts/oauth-test-osm.mjs` and, in another shell,
`node scripts/oauth-smoke.mjs`.

## Before enabling in production

Do one real sign-in with the deployment's registered OSM application and an
installed app. Expired interaction, code and token rows are not purged yet; a
retention job should delete them once their grant can no longer use them
(consumed codes and refresh tokens must stay while the grant is live, for
replay detection).
