/**
 * ESLint config aligned with @n8n/scan-community-package (recommended + no-console).
 * Lint compiled output under dist/ after `npm run build`.
 */
import { defineConfig } from 'eslint/config';
import { n8nCommunityNodesPlugin } from '@n8n/eslint-plugin-community-nodes';

export default defineConfig(
	n8nCommunityNodesPlugin.configs.recommended,
	{
		rules: {
			'no-console': 'error',
		},
	},
);
