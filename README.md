# n8n-nodes-svix-webhook-verify

An n8n community node that receives and verifies [Svix](https://www.svix.com/) webhook signatures. Built for [Clerk](https://clerk.com/) webhooks, but works with any service that uses Svix for webhook delivery.

## What it does

This node acts as a **webhook trigger** in your n8n workflow. It:

1. Receives incoming POST requests at a webhook URL
2. Verifies the Svix signature (`svix-id`, `svix-timestamp`, `svix-signature` headers)
3. Rejects unverified requests with a `400` error
4. Passes the verified payload into your workflow

Only webhooks with valid signatures trigger your workflow. Fake or tampered requests are blocked.

## Installation

1. In your n8n instance, go to **Settings > Community Nodes**
2. Click **Install**
3. Enter `n8n-nodes-svix-webhook-verify`
4. Click **Install**

## Setup

### 1. Get your webhook signing secret

- Go to your [Clerk Dashboard](https://dashboard.clerk.com/) > **Webhooks**
- Create or select an endpoint
- Copy the **Signing Secret** (starts with `whsec_`)

### 2. Configure the node in n8n

1. Add the **Svix Webhook Verify** trigger node to your workflow
2. Create a new credential and paste your signing secret
3. Copy the **webhook URL** shown in the node
4. Paste that URL as the endpoint in your Clerk Dashboard

### 3. Select event types (optional)

By default the node accepts all events. You can filter to specific Clerk event types:

- `user.created`, `user.updated`, `user.deleted`
- `session.created`, `session.ended`, `session.removed`, `session.revoked`
- `organization.created`, `organization.updated`, `organization.deleted`
- `organizationMembership.created`, `organizationMembership.updated`, `organizationMembership.deleted`
- `email.created`, `sms.created`

## Output

The node outputs the verified webhook payload with additional metadata fields:

```json
{
  "type": "user.created",
  "data": {
    "id": "user_2g7np...",
    "first_name": "John",
    "last_name": "Doe",
    "email_addresses": [...],
    ...
  },
  "timestamp": 1716883200,
  "_eventType": "user.created",
  "_svixId": "msg_3BU5u...",
  "_svixTimestamp": "1774531028"
}
```

| Field | Description |
|-------|-------------|
| `type` | The Clerk event type |
| `data` | The event payload from Clerk |
| `_eventType` | Same as `type`, for easy routing in IF nodes |
| `_svixId` | Svix message ID |
| `_svixTimestamp` | Svix delivery timestamp |

## Security

| Request | Response | Workflow |
|---------|----------|----------|
| No svix headers | `400 Missing required svix headers` | Not triggered |
| Invalid signature | `400 Webhook signature verification failed` | Not triggered |
| Valid signature | `200` | Triggered with payload |

## Compatibility

- **n8n version**: 0.5+ (n8n Nodes API v1)
- **Node.js**: 18.10+
- **Works with**: Clerk, or any service using Svix for webhook delivery

## License

MIT
