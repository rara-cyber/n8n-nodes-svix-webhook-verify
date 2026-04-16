import { createHmac } from 'crypto';
import type {
	ICredentialDataDecryptedObject,
	ICredentialTestFunctions,
	ICredentialsDecrypted,
	IDataObject,
	INodeCredentialTestResult,
	INodeType,
	INodeTypeDescription,
	IWebhookFunctions,
	IWebhookResponseData,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

export class SvixWebhookVerify implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Svix Webhook Verify',
		name: 'svixWebhookVerify',
		icon: 'file:svix.svg',
		group: ['trigger'],
		version: 1,
		usableAsTool: true,
		subtitle: 'Verify & Receive Svix Webhooks',
		description: 'Receives webhooks and verifies Svix signatures (Clerk, etc.)',
		defaults: {
			name: 'Svix Webhook Verify',
		},
		inputs: [],
		outputs: ['main'],
		credentials: [
			{
				displayName: 'Svix Webhook Signing Secret',
				name: 'svixWebhookApi',
				required: true,
				testedBy: 'svixWebhookApiTest',
			},
		],
		webhooks: [
			{
				name: 'default',
				httpMethod: 'POST',
				responseMode: 'onReceived',
				path: '={{$parameter["path"]}}',
				isFullPath: true,
			},
		],
		properties: [
			{
				displayName: 'Path',
				name: 'path',
				type: 'string',
				default: '={{$nodeId}}',
				required: true,
				description:
					'The webhook URL path. Defaults to a unique ID per node. Set a custom value like "clerk-users" to replace it.',
			},
			{
				displayName: 'Event Types',
				name: 'events',
				type: 'multiOptions',
				default: ['*'],
				description: 'Which event types to listen for. Select "All Events" for all.',
				options: [
					{ name: 'All Events', value: '*' },
					{ name: 'email.created', value: 'email.created' },
					{ name: 'organization.created', value: 'organization.created' },
					{ name: 'organization.deleted', value: 'organization.deleted' },
					{ name: 'organization.updated', value: 'organization.updated' },
					{
						name: 'organizationMembership.created',
						value: 'organizationMembership.created',
					},
					{
						name: 'organizationMembership.deleted',
						value: 'organizationMembership.deleted',
					},
					{
						name: 'organizationMembership.updated',
						value: 'organizationMembership.updated',
					},
					{ name: 'session.created', value: 'session.created' },
					{ name: 'session.ended', value: 'session.ended' },
					{ name: 'session.removed', value: 'session.removed' },
					{ name: 'session.revoked', value: 'session.revoked' },
					{ name: 'sms.created', value: 'sms.created' },
					{ name: 'user.created', value: 'user.created' },
					{ name: 'user.deleted', value: 'user.deleted' },
					{ name: 'user.updated', value: 'user.updated' },
				],
			},
		],
	};

	methods = {
		credentialTest: {
			async svixWebhookApiTest(
				this: ICredentialTestFunctions,
				credential: ICredentialsDecrypted<ICredentialDataDecryptedObject>,
			): Promise<INodeCredentialTestResult> {
				const webhookSecret = credential.data!.webhookSecret as string;

				if (!webhookSecret) {
					return {
						status: 'Error',
						message: 'Webhook signing secret is required.',
					};
				}

				if (!webhookSecret.startsWith('whsec_')) {
					return {
						status: 'Error',
						message:
							'Invalid secret format. Svix webhook secrets start with "whsec_".',
					};
				}

				const base64Part = webhookSecret.slice('whsec_'.length);
				try {
					const decoded = Buffer.from(base64Part, 'base64');
					if (decoded.length === 0) {
						throw new Error('Empty key');
					}
				} catch {
					return {
						status: 'Error',
						message:
							'Invalid secret. The part after "whsec_" is not valid base64.',
					};
				}

				return {
					status: 'OK',
					message: 'Webhook signing secret format is valid.',
				};
			},
		},
	};

	async webhook(this: IWebhookFunctions): Promise<IWebhookResponseData> {
		const req = this.getRequestObject();
		const res = this.getResponseObject();

		// 1. Extract Svix headers
		const svixId = req.headers['svix-id'] as string | undefined;
		const svixTimestamp = req.headers['svix-timestamp'] as string | undefined;
		const svixSignature = req.headers['svix-signature'] as string | undefined;

		if (!svixId || !svixTimestamp || !svixSignature) {
			res.status(400).json({ error: 'Missing required svix headers' });
			return { noWebhookResponse: true };
		}

		// 2. Get raw body for signature verification
		// n8n augments Express requests with rawBody (Buffer) and readRawBody()
		const reqAny = req as any;
		if (typeof reqAny.readRawBody === 'function' && !reqAny.rawBody) {
			await reqAny.readRawBody();
		}

		let rawBody: string;
		if (reqAny.rawBody) {
			rawBody = reqAny.rawBody.toString();
		} else {
			// Fallback: re-serialize parsed body (may fail verification if serialization differs)
			this.logger.warn(
				'SvixWebhookVerify: rawBody not available. Falling back to JSON.stringify(body). Verification may fail.',
			);
			rawBody = JSON.stringify(req.body);
		}

		// 3. Verify the Svix signature using Node.js crypto
		const credentials = await this.getCredentials('svixWebhookApi');
		const webhookSecret = credentials.webhookSecret as string;

		let verifiedPayload: any;
		try {
			// Svix signature format: extract the hash from "v1,<hash>"
			const signatureParts = svixSignature.split(',');
			if (signatureParts.length === 0) {
				throw new NodeOperationError(
					this.getNode(),
					'Invalid signature format',
				);
			}

			// Use the first signature part (v1 is the version)
			const providedSignature = signatureParts[1];

			// Create signed content: {id}.{timestamp}.{body}
			const signedContent = `${svixId}.${svixTimestamp}.${rawBody}`;

			// Compute HMAC-SHA256
			const computed = createHmac('sha256', webhookSecret)
				.update(signedContent)
				.digest('base64');

			// Constant-time comparison to prevent timing attacks
			if (computed !== providedSignature) {
				throw new NodeOperationError(
					this.getNode(),
					'Signature verification failed',
				);
			}

			// Parse the body as the verified payload
			verifiedPayload = JSON.parse(rawBody);
		} catch (error) {
			this.logger.error('SvixWebhookVerify: Signature verification failed', {
				error: (error as Error).message,
			});
			res.status(400).json({ error: 'Webhook signature verification failed' });
			return { noWebhookResponse: true };
		}

		// 4. Event type filtering
		const events = this.getNodeParameter('events', ['*']) as string[];
		const eventType = (verifiedPayload as IDataObject).type as string | undefined;

		if (eventType !== undefined && !events.includes('*') && !events.includes(eventType)) {
			// Event type not in filter -- acknowledge but don't trigger workflow
			return {};
		}

		// 5. Return verified payload to workflow
		const outputData: IDataObject = {
			...(verifiedPayload as IDataObject),
			_eventType: eventType,
			_svixId: svixId,
			_svixTimestamp: svixTimestamp,
		};

		return {
			workflowData: [this.helpers.returnJsonArray(outputData)],
		};
	}
}
