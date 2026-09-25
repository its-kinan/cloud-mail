const encoder = new TextEncoder();

// PBKDF2-HMAC-SHA-256 cost factor for new password hashes.
//
// The Workers WebCrypto runtime rejects iteration counts above 100000, so the
// default and the cap sit at that ceiling. 100k is below OWASP's 210k/600k
// guidance, but it is the most the platform allows; raise it via the
// `pbkdf2_iterations` env var only if the runtime ever lifts the cap (it will
// be clamped). Stored hashes embed their own iteration count, so changing this
// later is safe: existing hashes keep verifying, new hashes use the new cost.
export const PBKDF2_DEFAULT_ITERATIONS = 100000;
const PBKDF2_MIN_ITERATIONS = 10000;
const PBKDF2_MAX_ITERATIONS = 100000;
const PBKDF2_KEY_LEN_BYTES = 32;
const PBKDF2_HASH_PREFIX = 'pbkdf2';

export const b64encode = (bytes) => btoa(String.fromCharCode(...bytes));
export const b64decode = (str) => Uint8Array.from(atob(str), (ch) => ch.charCodeAt(0));

// Constant-time string comparison. Not a substitute for a slow KDF, but avoids
// leaking hash-prefix information through response timing.
export function timingSafeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string') return false;
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

async function pbkdf2Sha256(password, saltBytes, iterations) {
	const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations },
		key,
		PBKDF2_KEY_LEN_BYTES * 8
	);
	return new Uint8Array(bits);
}

const saltHashUtils = {

	generateSalt(length = 16) {
		const array = new Uint8Array(length);
		crypto.getRandomValues(array);
		return b64encode(array);
	},

	// Env-tunable cost factor, clamped to a sane range.
	resolveIterations(env) {
		const raw = parseInt(env?.pbkdf2_iterations, 10);
		if (!Number.isFinite(raw)) return PBKDF2_DEFAULT_ITERATIONS;
		return Math.min(PBKDF2_MAX_ITERATIONS, Math.max(PBKDF2_MIN_ITERATIONS, raw));
	},

	// New hashes: pbkdf2$<iterations>$<base64>. The legacy single-round
	// SHA-256(salt + password) format has no prefix (see isLegacyHash).
	async hashPassword(password, iterations = PBKDF2_DEFAULT_ITERATIONS) {
		const saltBytes = new Uint8Array(16);
		crypto.getRandomValues(saltBytes);
		const derived = await pbkdf2Sha256(password, saltBytes, iterations);
		return { salt: b64encode(saltBytes), hash: `${PBKDF2_HASH_PREFIX}$${iterations}$${b64encode(derived)}` };
	},

	isLegacyHash(storedHash) {
		return typeof storedHash !== 'string' || !storedHash.startsWith(PBKDF2_HASH_PREFIX + '$');
	},

	async verifyPassword(inputPassword, salt, storedHash) {
		if (!this.isLegacyHash(storedHash)) {
			const parts = storedHash.split('$');
			const iterations = parseInt(parts[1], 10);
			const expectedB64 = parts[2];
			if (!Number.isFinite(iterations) || !expectedB64) return false;
			const derived = await pbkdf2Sha256(inputPassword, b64decode(salt), iterations);
			return timingSafeEqual(b64encode(derived), expectedB64);
		}
		// Legacy path: single-round SHA-256(salt + password). Still accepted so
		// existing users can log in; callers rehash on success (see login-service).
		const digest = await crypto.subtle.digest('SHA-256', encoder.encode(salt + inputPassword));
		return timingSafeEqual(b64encode(new Uint8Array(digest)), storedHash);
	},

	genRandomPwd(length = 8) {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		let result = '';
		for (let i = 0; i < length; i++) {
			result += chars.charAt(Math.floor(Math.random() * chars.length));
		}
		return result;
	}
};

export default saltHashUtils;
