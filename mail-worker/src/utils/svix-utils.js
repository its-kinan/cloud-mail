import { timingSafeEqual, b64encode, b64decode } from './crypto-utils.js';

const encoder = new TextEncoder();
// Reject replays older/newer than this (Svix recommends ~5 minutes).
const TIMESTAMP_TOLERANCE_SECONDS = 300;

/**
 * Verify a Resend (Svix) webhook signature.
 * https://docs.svix.com/receiving/verifying-payloads/how
 *
 * @param {{svixId: string, svixTimestamp: string, svixSignature: string}} headers
 * @param {string} rawBody the exact raw request body bytes as text
 * @param {string} secret the endpoint signing secret (with or without the `whsec_` prefix)
 * @returns {Promise<boolean>}
 */
export async function verifySvixSignature(headers, rawBody, secret) {
	const { svixId, svixTimestamp, svixSignature } = headers || {};

	if (!svixId || !svixTimestamp || !svixSignature || !secret) return false;

	const timestamp = parseInt(svixTimestamp, 10);
	if (!Number.isFinite(timestamp)) return false;

	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_SECONDS) return false;

	const secretBytes = b64decode(secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret);
	const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const signedContent = encoder.encode(`${svixId}.${svixTimestamp}.${rawBody}`);
	const signature = await crypto.subtle.sign('HMAC', key, signedContent);
	const expectedB64 = b64encode(new Uint8Array(signature));

	// The header can carry multiple space-separated signatures during rotation.
	return svixSignature.split(' ').some((candidate) => {
		const value = candidate.startsWith('v1,') ? candidate.slice(3) : candidate;
		return timingSafeEqual(value, expectedB64);
	});
}
