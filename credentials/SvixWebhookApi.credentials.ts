import type { ICredentialType, INodeProperties, Icon } from 'n8n-workflow';

export class SvixWebhookApi implements ICredentialType {
	name = 'svixWebhookApi';

	displayName = 'Svix Webhook Signing Secret';

	documentationUrl = 'https://docs.svix.com/receiving/verifying-payloads/how';

	icon: Icon = 'file:../nodes/SvixWebhookVerify/svix.svg';

	properties: INodeProperties[] = [
		{
			displayName: 'Webhook Signing Secret',
			name: 'webhookSecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'The Svix webhook signing secret (starts with "whsec_"). Found in your Clerk Dashboard under Webhooks.',
		},
	];
}
