import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class AIGuardApi implements ICredentialType {
	name = 'aiGuardApi';
	displayName = 'Zscaler AI Guard API';
	documentationUrl = 'https://help.zscaler.com/ai-guard';
	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'The API key for Zscaler AI Guard API (Bearer token)',
		},
		{
			displayName: 'Cloud',
			name: 'cloud',
			type: 'string',
			default: 'us1',
			required: true,
			description:
				'The Zscaler cloud for your tenancy (e.g. us1). Used to build the API URL: https://api.{cloud}.zseclipse.net',
		},
		{
			displayName: 'Override URL',
			name: 'overrideUrl',
			type: 'string',
			default: '',
			placeholder: 'https://api.example.zseclipse.net',
			description:
				'Optional: Override the API base URL entirely. When set, the Cloud field is ignored. Equivalent to AIGUARD_OVERRIDE_URL in the SDK.',
		},
		{
			displayName: 'Policy ID',
			name: 'policyId',
			type: 'string',
			default: '',
			placeholder: 'e.g. 760 or leave empty for auto-resolution',
			description:
				'Optional: The AI Guard policy ID. When set, uses execute-policy endpoint. When empty, uses resolve-and-execute-policy for automatic policy resolution.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
				'Content-Type': 'application/json',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL:
				'={{$credentials.overrideUrl ? $credentials.overrideUrl : "https://api." + $credentials.cloud + ".zseclipse.net"}}',
			url: '={{$credentials.policyId ? "/v1/detection/execute-policy" : "/v1/detection/resolve-and-execute-policy"}}',
			method: 'POST',
			body: '={{ $credentials.policyId ? { "content": "Hello, credential test.", "direction": "IN", "policyId": parseInt($credentials.policyId) } : { "content": "Hello, credential test.", "direction": "IN" } }}',
		},
		rules: [
			{
				type: 'responseCode',
				properties: {
					message: 'Credential test successful',
					value: 200,
				},
			},
		],
	};
}
