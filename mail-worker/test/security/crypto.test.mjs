import { test } from 'node:test';
import assert from 'node:assert/strict';
import cryptoUtils, {
	PBKDF2_DEFAULT_ITERATIONS,
	timingSafeEqual,
	b64encode,
	b64decode
} from '../../src/utils/crypto-utils.js';

const enc = new TextEncoder();

// --- helpers ---------------------------------------------------------------

// Reproduce the legacy scheme: base64( SHA-256( salt + password ) )
async function legacyHash(password, salt) {
	const digest = await crypto.subtle.digest('SHA-256', enc.encode(salt + password));
	return b64encode(new Uint8Array(digest));
}

// --- hash / verify roundtrip -----------------------------------------------

test('hashPassword -> verifyPassword roundtrip succeeds', async () => {
	const { salt, hash } = await cryptoUtils.hashPassword('correct horse', 15000);
	assert.match(hash, /^pbkdf2\$15000\$/);
	assert.equal(await cryptoUtils.verifyPassword('correct horse', salt, hash), true);
});

test('wrong password fails verification', async () => {
	const { salt, hash } = await cryptoUtils.hashPassword('correct horse', 15000);
	assert.equal(await cryptoUtils.verifyPassword('wrong password', salt, hash), false);
});

test('embedded iteration count is honored (not the default)', async () => {
	// Hash with a custom cost, then verify without passing the cost anywhere:
	// verifyPassword must read it from the stored hash.
	const { salt, hash } = await cryptoUtils.hashPassword('pw', 42000);
	assert.ok(hash.startsWith('pbkdf2$42000$'));
	assert.equal(await cryptoUtils.verifyPassword('pw', salt, hash), true);
});

test('tampered hash payload fails verification', async () => {
	const { salt, hash } = await cryptoUtils.hashPassword('pw', 15000);
	const tampered = hash.slice(0, -4) + 'AAAA';
	assert.equal(await cryptoUtils.verifyPassword('pw', salt, tampered), false);
});

test('malformed pbkdf2 hash fails closed', async () => {
	const { salt } = await cryptoUtils.hashPassword('pw', 15000);
	assert.equal(await cryptoUtils.verifyPassword('pw', salt, 'pbkdf2$notanumber$AAAA'), false);
	assert.equal(await cryptoUtils.verifyPassword('pw', salt, 'pbkdf2$15000$'), false);
});

// --- legacy migration path --------------------------------------------------

test('legacy single-round SHA-256 hashes still verify', async () => {
	const salt = cryptoUtils.generateSalt();
	const stored = await legacyHash('old-password', salt);
	assert.equal(cryptoUtils.isLegacyHash(stored), true);
	assert.equal(await cryptoUtils.verifyPassword('old-password', salt, stored), true);
	assert.equal(await cryptoUtils.verifyPassword('nope', salt, stored), false);
});

test('new hashes are not flagged as legacy', async () => {
	const { hash } = await cryptoUtils.hashPassword('pw', 15000);
	assert.equal(cryptoUtils.isLegacyHash(hash), false);
});

// --- iterations tuning -------------------------------------------------------

test('resolveIterations defaults, parses env, and clamps', () => {
	assert.equal(cryptoUtils.resolveIterations(undefined), PBKDF2_DEFAULT_ITERATIONS);
	assert.equal(cryptoUtils.resolveIterations({}), PBKDF2_DEFAULT_ITERATIONS);
	assert.equal(cryptoUtils.resolveIterations({ pbkdf2_iterations: '600000' }), 100000); // clamped to the Workers runtime ceiling
	assert.equal(cryptoUtils.resolveIterations({ pbkdf2_iterations: 'garbage' }), PBKDF2_DEFAULT_ITERATIONS);
	assert.equal(cryptoUtils.resolveIterations({ pbkdf2_iterations: '100' }), 10000); // clamped up
	assert.equal(cryptoUtils.resolveIterations({ pbkdf2_iterations: '99999999' }), 100000); // clamped down to the Workers runtime ceiling
});

// --- timingSafeEqual ----------------------------------------------------------

test('timingSafeEqual compares without early exit on content', () => {
	assert.equal(timingSafeEqual('abc', 'abc'), true);
	assert.equal(timingSafeEqual('abc', 'abd'), false);
	assert.equal(timingSafeEqual('abc', 'abcd'), false);
	assert.equal(timingSafeEqual(null, 'abc'), false);
});

test('b64encode/b64decode roundtrip', () => {
	const bytes = new Uint8Array([0, 1, 2, 250, 255]);
	assert.deepEqual(b64decode(b64encode(bytes)), bytes);
});
