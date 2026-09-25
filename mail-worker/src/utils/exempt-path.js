// Paths that bypass the JWT auth middleware in security.js.
//
// Matching rule: exact path, or a sub-path under it (`path === p || path.startsWith(p + '/')`).
// The old code used a bare `startsWith`, so e.g. `/loginX` would also have been exempt.
//
// Notes on what stays public and why:
// - `/oss/*` serves attachments by content-addressed key (sha256 of the file
//   content). The browser fetches these via plain <img> tags, which can't send
//   the auth header, so they are capability URLs by design: unguessable, but
//   anyone holding a link can download. Acceptable for mail attachments;
//   do NOT put anything here that needs real access control.
// - `/webhooks` is the Resend delivery-status webhook; it is authenticated by
//   Svix signature verification (see utils/svix-utils.js), not by JWT.
// - `/init/:secret` is the one-time DB bootstrap, guarded by its own secret.
// - `/test` was removed: test-api.js registers no routes, so the exemption was
//   dead surface area.
export const EXEMPT_PATHS = [
	'/login',
	'/register',
	'/oss',
	'/setting/websiteConfig',
	'/webhooks',
	'/init',
	'/public/genToken',
	'/telegram',
	'/oauth'
];

export function isExemptPath(path) {
	if (typeof path !== 'string') return false;
	return EXEMPT_PATHS.some((p) => path === p || path.startsWith(p + '/'));
}
