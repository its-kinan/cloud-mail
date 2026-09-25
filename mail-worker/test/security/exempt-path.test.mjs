import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isExemptPath, EXEMPT_PATHS } from '../../src/utils/exempt-path.js';

test('exact exempt paths pass', () => {
	for (const p of ['/login', '/register', '/webhooks', '/init', '/telegram', '/oauth', '/setting/websiteConfig', '/public/genToken', '/oss']) {
		assert.equal(isExemptPath(p), true, p);
	}
});

test('sub-paths of exempt prefixes pass', () => {
	assert.equal(isExemptPath('/init/abc123'), true);
	assert.equal(isExemptPath('/oss/some-key.png'), true);
	assert.equal(isExemptPath('/telegram/bind'), true);
	assert.equal(isExemptPath('/oauth/github'), true);
	assert.equal(isExemptPath('/login/'), true);
});

test('bare-prefix squatting no longer exempts', () => {
	// The old code used path.startsWith(item): '/loginX' would bypass auth.
	for (const p of ['/loginX', '/loginfoo', '/register2', '/webhooks-evil', '/ossBackup', '/test']) {
		assert.equal(isExemptPath(p), false, p);
	}
});

test('/test exemption was removed (dead route)', () => {
	assert.equal(EXEMPT_PATHS.includes('/test'), false);
	assert.equal(isExemptPath('/test'), false);
	assert.equal(isExemptPath('/test/anything'), false);
});

test('protected paths are not exempt', () => {
	for (const p of ['/email/send', '/user/list', '/public/emailList', '/public/addUser', '/allEmail/list', '/api/login']) {
		assert.equal(isExemptPath(p), false, p);
	}
});

test('non-string input fails closed', () => {
	assert.equal(isExemptPath(undefined), false);
	assert.equal(isExemptPath(null), false);
});
