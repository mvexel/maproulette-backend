// Local-only OSM stand-in for browser acceptance tests. Never use as an identity provider.
// This server binds loopback and intentionally identifies a synthetic user without a password.
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const clientId = 'oauth-test-upstream';
const secret = process.env.OAUTH_TEST_OSM_SECRET;
if (!secret) throw new Error('Set OAUTH_TEST_OSM_SECRET for this local test server');
const callback = 'http://127.0.0.1:9000/oauth/callback';
const codes = new Map();
const tokens = new Map();
const escape = value => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;')
  .replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const equal = (left, right) => {
  const a = Buffer.from(left ?? '');
  const b = Buffer.from(right ?? '');
  return a.length === b.length && timingSafeEqual(a, b);
};
const server = createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Referrer-Policy', 'no-referrer');
  const url = new URL(request.url, 'http://127.0.0.1:9001');
  const json = (status, value) => {
    response.writeHead(status, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(value));
  };
  if (request.method === 'GET' && url.pathname === '/oauth2/authorize') {
    if (url.searchParams.get('client_id') !== clientId ||
        url.searchParams.get('redirect_uri') !== callback ||
        url.searchParams.get('response_type') !== 'code' ||
        !url.searchParams.get('state')) return json(400, { error: 'invalid_request' });
    const code = randomBytes(32).toString('base64url');
    codes.set(code, Date.now() + 120000);
    const destination = new URL(callback);
    destination.searchParams.set('code', code);
    destination.searchParams.set('state', url.searchParams.get('state'));
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
      <h1>Local OSM test server</h1><p>This is a synthetic test identity, not OpenStreetMap login.</p>
      <p><a href="${escape(destination.toString())}">Continue as SDK Test Mapper</a></p>`);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/oauth2/token') {
    let body = '';
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 8192) return json(413, { error: 'invalid_request' });
    }
    const form = new URLSearchParams(body);
    if (form.get('client_id') !== clientId || !equal(form.get('client_secret'), secret) ||
        form.get('redirect_uri') !== callback || form.get('grant_type') !== 'authorization_code')
      return json(400, { error: 'invalid_client' });
    const expiry = codes.get(form.get('code'));
    codes.delete(form.get('code'));
    if (!expiry || expiry <= Date.now()) return json(400, { error: 'invalid_grant' });
    const accessToken = randomBytes(32).toString('base64url');
    tokens.set(accessToken, Date.now() + 120000);
    return json(200, { access_token: accessToken, token_type: 'Bearer', scope: 'read_prefs' });
  }
  if (request.method === 'GET' && url.pathname === '/api/0.6/user/details') {
    const token = (request.headers.authorization ?? '').replace(/^Bearer /, '');
    if ((tokens.get(token) ?? 0) <= Date.now()) return json(401, { error: 'invalid_token' });
    response.writeHead(200, { 'Content-Type': 'text/xml' });
    response.end('<osm><user id="1900000042" display_name="SDK Test Mapper" account_created="2020-01-01T00:00:00Z"><description>Synthetic local authentication test</description></user></osm>');
    return;
  }
  json(404, { error: 'not_found' });
});
server.listen(9001, '127.0.0.1', () => console.log('Local synthetic OSM server on 127.0.0.1:9001'));
const cleanup = setInterval(() => {
  for (const store of [codes, tokens]) for (const [key, expiry] of store)
    if (expiry <= Date.now()) store.delete(key);
}, 60000);
cleanup.unref();
