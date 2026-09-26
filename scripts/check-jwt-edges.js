// Cases check-jwt.js does not reach: inputs that parse as JSON but are not objects,
// signatures that only match under a lenient base64url decoder, and claim types that
// a loose comparison would let through.
// Run: node scripts/check-jwt-edges.js

import { createHmac } from 'node:crypto';
import { verifyAccessToken, signToken } from '../server/auth.js';
import { HttpError } from '../server/http.js';

const SECRET = 'test-secret';
const nowSec = () => Math.floor(Date.now() / 1000);
const enc = (s) => Buffer.from(s).toString('base64url');
const json = (v) => enc(JSON.stringify(v));
const sign = (h, p) => createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
// Sign exactly the segments given, so the signature is valid and only the content is odd.
const raw = (h, p) => `${h}.${p}.${sign(h, p)}`;

const claims = (over = {}) => ({
  iss: 'remoteops', aud: 'remoteops-api', sub: 'usr_x', org: 'org_x', role: 'viewer',
  pv: 1, jti: 'j1', iat: nowSec(), exp: nowSec() + 900, ...over,
});
const HS = json({ alg: 'HS256', typ: 'JWT' });

let pass = 0, fail = 0;
const outcome = (token) => {
  try { verifyAccessToken(token, SECRET); return 'accepted'; }
  catch (e) { return e instanceof HttpError ? `${e.status} ${e.code}` : `${e.constructor.name}: ${e.message}`; }
};
const check = (label, token, want = '401 UNAUTHENTICATED') => {
  const got = outcome(token);
  got === want ? pass++ : fail++;
  console.log(`${got === want ? '  ok  ' : ' FAIL '} ${label.padEnd(52)} ${got === want ? '' : `got ${got}`}`);
};

const good = signToken(claims(), SECRET);
const [gh, gp, gs] = good.split('.');

console.log('\n== JSON that is not an object ==');
check('header is JSON null', raw(json(null), json(claims())));
check('header is a JSON array', raw(json(['HS256']), json(claims())));
check('header is a JSON string', raw(json('HS256'), json(claims())));
check('payload is JSON null', raw(HS, json(null)));
check('payload is a JSON array', raw(HS, json([claims()])));
check('payload is a JSON number', raw(HS, json(42)));

console.log('\n== signature only valid to a lenient decoder ==');
check('junk appended to a valid signature', `${gh}.${gp}.${gs}!!`);
check('junk prepended to a valid signature', `${gh}.${gp}.!${gs}`);
check('padding appended to a valid signature', `${gh}.${gp}.${gs}=`);

console.log('\n== claim types ==');
check('aud as an array containing ours', signToken(claims({ aud: ['remoteops-api'] }), SECRET));
check('jti as a number', signToken(claims({ jti: 7 }), SECRET));
check('exp as a numeric string', signToken(claims({ exp: `${nowSec() + 900}` }), SECRET));
check('token is a number', 12345);
check('token is an object', { token: good });

console.log('\n== still accepted ==');
check('the good token', good, 'accepted');

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
