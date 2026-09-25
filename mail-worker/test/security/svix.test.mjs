import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifySvixSignature } from '../../src/utils/svix-utils.js';
import { b64encode } from '../../src/utils/crypto-utils.js';

const enc = new TextEncoder();

// --- helpers -----------------------------------------------------------------

// Build a genuinely valid Svix signature the same way Resend does.
async function sign(secretB64, id, ts, body) {
	const keyBytes = Uint8Array.from(atob(secretB64), (c) => c.charCodeAt(0));
	const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${id}.${ts}.${body}`));
	return `v1,${b64encode(new Uint8Array(sig))}`;
}

function freshHeaders() {
	const secretBytes = new Uint8Array(32);
	crypto.getRandomValues(secretBytes);
	const secret = b64encode(secretBytes);
	const id = 'msg_test123';
	const ts = String(Math.floor(Date.now() / 1000));
	const body = JSON.stringify({ type: 'email.delivered', data: { email_id: 'abc' } });
	return { secret, id, ts, body };
}

async function validCase() {
	const { secret, id, ts, body } = freshHeaders();
	const sig = await sign(secret, id, ts, body);
	return { secret, headers: { svixId: id, svixTimestamp: ts, svixSignature: sig }, body };
}

// --- tests --------------------------------------------------------------------

test('valid signature verifies', async () => {
	const { secret, headers, body } = await validCase();
	assert.equal(await verifySvixSignature(headers, body, secret), true);
});

test('whsec_ prefixed secret is accepted', async () => {
	const { secret, headers, body } = await validCase();
	assert.equal(await verifySvixSignature(headers, body, `whsec_${secret}`), true);
});

test('tampered body fails', async () => {
	const { secret, headers, body } = await validCase();
	assert.equal(await verifySvixSignature(headers, body + ' ', secret), false);
});

test('wrong secret fails', async () => {
	const { headers, body } = await validCase();
	const other = b64encode(crypto.getRandomValues(new Uint8Array(32)));
	assert.equal(await verifySvixSignature(headers, body, other), false);
});

test('tampered signature fails', async () => {
	const { secret, headers, body } = await validCase();
	const bad = { ...headers, svixSignature: 'v1,' + 'A'.repeat(44) };
	assert.equal(await verifySvixSignature(bad, body, secret), false);
});

test('stale timestamp fails (replay protection)', async () => {
	const { secret, id, ts, body } = freshHeaders();
	const oldTs = String(Math.floor(Date.now() / 1000) - 3600);
	const sig = await sign(secret, id, oldTs, body);
	const headers = { svixId: id, svixTimestamp: oldTs, svixSignature: sig };
	assert.equal(await verifySvixSignature(headers, body, secret), false);
});

test('future timestamp beyond tolerance fails', async () => {
	const { secret, id, body } = freshHeaders();
	const futureTs = String(Math.floor(Date.now() / 1000) + 3600);
	const sig = await sign(secret, id, futureTs, body);
	const headers = { svixId: id, svixTimestamp: futureTs, svixSignature: sig };
	assert.equal(await verifySvixSignature(headers, body, secret), false);
});

test('missing headers or secret fail closed', async () => {
	const { secret, headers, body } = await validCase();
	assert.equal(await verifySvixSignature({ ...headers, svixId: undefined }, body, secret), false);
	assert.equal(await verifySvixSignature(headers, body, ''), false);
	assert.equal(await verifySvixSignature(headers, body, undefined), false);
});

test('key rotation: one of several signatures may match', async () => {
	const { secret, headers, body } = await validCase();
	const rotated = { ...headers, svixSignature: `v1,${'B'.repeat(43)}= ${headers.svixSignature}` };
	assert.equal(await verifySvixSignature(rotated, body, secret), true);
});

test('non-numeric timestamp fails', async () => {
	const { secret, headers, body } = await validCase();
	assert.equal(await verifySvixSignature({ ...headers, svixTimestamp: 'not-a-time' }, body, secret), false);
});
