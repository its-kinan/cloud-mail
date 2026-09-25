import resendService from '../service/resend-service';
import { verifySvixSignature } from '../utils/svix-utils.js';
import app from '../hono/hono';

// Resend delivery-status webhook. Previously this endpoint accepted any JSON
// body with no authentication, so anyone could flip a message's status to
// delivered/bounced/failed. It is now verified with the Svix signature Resend
// attaches to every webhook call.
//
// Setup: in the Resend dashboard, open Webhooks -> your endpoint and copy the
// "Signing Secret", then set it as a worker secret:
//
//   wrangler secret put resend_webhook_secret
//
// Requests are rejected (fail closed) when the secret is not configured or the
// signature does not verify.
app.post('/webhooks',async (c) => {
	try {
		const secret = c.env.resend_webhook_secret;

		if (!secret) {
			return c.text('webhook secret not configured', 500);
		}

		// The signature covers the exact raw body, so it must be read as text
		// before JSON parsing.
		const rawBody = await c.req.text();

		const verified = await verifySvixSignature(
			{
				svixId: c.req.header('svix-id'),
				svixTimestamp: c.req.header('svix-timestamp'),
				svixSignature: c.req.header('svix-signature')
			},
			rawBody,
			secret
		);

		if (!verified) {
			return c.text('invalid webhook signature', 401);
		}

		await resendService.webhooks(c, JSON.parse(rawBody));
		return c.text('success', 200)
	} catch (e) {
		return  c.text(e.message, 500)
	}
})
