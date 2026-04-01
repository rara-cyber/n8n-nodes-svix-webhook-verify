import { config } from '@n8n/node-cli/eslint';

export default [
	...config,

	{
		ignores: ['**/__tests__/**'],
	},

	{
		rules: {
			'@typescript-eslint/no-explicit-any': 'off',
		},
	},
];
