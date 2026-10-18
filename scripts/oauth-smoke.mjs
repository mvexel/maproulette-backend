// Exercises only the explicitly local synthetic OAuth setup described in docs/oauth-provider.md.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

const base = 'http://127.0.0.1:9000';
const clientId = 'example-app';
const redirectUri = 'org.maproulette.example:/oauth2redirect';
const post = (path, fields) => fetch(base + path, {
  method: 'POST', redirect: 'manual', body: new URLSearchParams(fields),
});
const identity = token => fetch(base + '/oauth/me', {
  headers: { Authorization: `Bearer ${token}` }, redirect: 'manual',
});
async function login() {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(32).toString('base64url');
  const query = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'tasks:read', state, code_challenge_method: 'S256',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
  });
  const start = await fetch(base + '/oauth/authorize?' + query, { redirect: 'manual' });
  assert.equal(start.status, 303, 'authorization redirect');
  const upstream = new URL(start.headers.get('location'));
  assert.equal(upstream.origin, 'http://127.0.0.1:9001', 'refuse non-test OSM provider');
  const cookie = start.headers.get('set-cookie').split(';')[0];
  const testPage = await fetch(upstream, { redirect: 'manual' });
  assert.equal(testPage.status, 200, 'synthetic OSM authorization');
  const html = await testPage.text();
  assert.ok(html.includes('Local OSM test server'));
  const callback = new URL(html.match(/href="([^"]+)"/)[1].replaceAll('&amp;', '&'));
  assert.equal(callback.origin, base);
  const consent = await fetch(callback, { headers: { Cookie: cookie }, redirect: 'manual' });
  assert.equal(consent.status, 200, 'verified OSM callback');
  const consentHtml = await consent.text();
  assert.ok(consentHtml.includes('SDK Test Mapper'));
  const fields = new URLSearchParams({
    interaction: consentHtml.match(/name="interaction" value="([^"]+)"/)[1],
    csrf: consentHtml.match(/name="csrf" value="([^"]+)"/)[1], decision: 'allow',
  });
  const approved = await fetch(base + '/oauth/consent', {
    method: 'POST', body: fields, headers: { Cookie: cookie }, redirect: 'manual',
  });
  assert.equal(approved.status, 303, 'consent redirect');
  const native = new URL(approved.headers.get('location'));
  assert.equal(native.origin, new URL(redirectUri).origin);
  assert.equal(native.protocol + native.pathname, redirectUri);
  assert.equal(native.searchParams.get('state'), state);
  const exchange = await post('/oauth/token', {
    grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectUri,
    code: native.searchParams.get('code'), code_verifier: verifier,
  });
  assert.equal(exchange.status, 200, 'PKCE code exchange');
  const tokens = await exchange.json();
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.scope, 'tasks:read');
  return tokens;
}

const tokens = await login();
const me = await identity(tokens.access_token);
assert.equal(me.status, 200);
const user = await me.json();
assert.equal(user.displayName, 'SDK Test Mapper');
assert.deepEqual(Object.keys(user).sort(), ['displayName', 'id', 'osmId', 'scope']);
for (const route of ['/api/v2/user/whoami', '/api/v2/task/1/start', '/api/v2/task/1/release']) {
  const forbidden = await fetch(base + route, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(forbidden.status, 403, 'scoped credential denied on sensitive route');
}
const refresh = await post('/oauth/token', {
  grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens.refresh_token,
});
assert.equal(refresh.status, 200);
const rotated = await refresh.json();
assert.notEqual(rotated.refresh_token, tokens.refresh_token);
assert.equal((await identity(rotated.access_token)).status, 200);
const replay = await post('/oauth/token', {
  grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens.refresh_token,
});
assert.equal(replay.status, 400);
assert.equal((await identity(rotated.access_token)).status, 401, 'replay revokes family');
const second = await login();
assert.equal((await post('/oauth/revoke', { client_id: clientId, token: second.refresh_token })).status, 200);
assert.equal((await identity(second.access_token)).status, 401, 'logout revocation');
console.log('PASS local browser/consent/PKCE, safe identity, route scope, refresh rotation/replay and revocation');
